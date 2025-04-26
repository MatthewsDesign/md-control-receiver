<?php

require_once plugin_dir_path(__DIR__) . 'auth/middleware.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

add_action('rest_api_init', function () {
    // Site Ping
    register_rest_route('md-control/v1', '/ping', [
        'methods' => 'POST',
        'callback' => 'md_control_ping',
        'permission_callback' => 'md_control_authenticate',
    ]);

    // Update Status Endpoint
    register_rest_route('md-control/v1', '/update-status', [
        'methods' => 'GET',
        'callback' => 'md_control_get_update_status',
        'permission_callback' => 'md_control_authenticate',
    ]);

    // Users
    register_rest_route('md-control/v1', '/users', [
        'methods' => 'GET',
        'callback' => 'md_control_list_users',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/users', [
        'methods' => 'POST',
        'callback' => 'md_control_create_user',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/users/(?P<id>\d+)', [
        'methods' => 'POST',
        'callback' => 'md_control_update_user',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/users/(?P<id>\d+)', [
        'methods' => 'DELETE',
        'callback' => 'md_control_delete_user',
        'permission_callback' => 'md_control_authenticate',
    ]);

    // Backups
    register_rest_route('md-control/v1', '/backup', [
        'methods' => 'POST',
        'callback' => 'md_control_trigger_backup',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/backup/status', [
        'methods' => 'GET',
        'callback' => 'md_control_get_latest_backup',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/backup/download', [
        'methods' => 'GET',
        'callback' => 'md_control_download_backup',
        'permission_callback' => 'md_control_authenticate',
        'args' => [
            'file' => [
                'required' => true,
                'validate_callback' => fn($value) => preg_match('/^[a-zA-Z0-9._-]+\.wpress$/', $value),
            ]
        ]
    ]);
});

// === One-Click Login ===

add_action('init', function () {
    if (!isset($_GET['user'], $_GET['expires'], $_GET['sig'])) return;
    if (!str_contains($_SERVER['REQUEST_URI'], 'wp-login.php')) return;

    $email = sanitize_email($_GET['user']);
    $expires = intval($_GET['expires']);
    $sig = sanitize_text_field($_GET['sig']);

    if (time() > $expires) wp_die('Login link expired.');

    $secret = get_option('md_control_api_key');
    $payload = "user=$email&expires=$expires";
    $expected = hash_hmac('sha256', $payload, $secret);

    if (!hash_equals($expected, $sig)) wp_die('Invalid signature.');

    $user = get_user_by('email', $email);
    if (!$user) wp_die('User not found.');

    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID);

    $redirect = isset($_GET['redirect_to']) ? esc_url_raw($_GET['redirect_to']) : admin_url();
    wp_redirect($redirect);
    exit;
});


// === Handlers ===

function md_control_ping(WP_REST_Request $request) {
    $plugin_updates = get_site_transient('update_plugins');
    $theme_updates = get_site_transient('update_themes');
    $core_updates = get_site_transient('update_core');

    $plugin_update_count = isset($plugin_updates->response) ? count($plugin_updates->response) : 0;
    $theme_update_count = isset($theme_updates->response) ? count($theme_updates->response) : 0;
    $core_update_count = 0;
    if (!empty($core_updates->updates)) {
        foreach ($core_updates->updates as $update) {
            if (isset($update->response) && $update->response === 'upgrade') {
                $core_update_count++;
            }
        }
    }

    return [
        'site_name' => get_bloginfo('name'),
        'url' => home_url(),
        'updates' => [
            'plugins' => $plugin_update_count,
            'themes' => $theme_update_count,
            'core' => $core_update_count,
            'total' => $plugin_update_count + $theme_update_count + $core_update_count,
        ],
    ];
}

function md_control_create_user(WP_REST_Request $request) {
    $username = sanitize_user($request->get_param('username'));
    $email = sanitize_email($request->get_param('email'));
    $password = $request->get_param('password');
    $role = sanitize_text_field($request->get_param('role'));

    if (!$username || !$email || !$password || !$role) {
        return new WP_Error('missing_fields', 'Missing one or more required fields.', ['status' => 400]);
    }

    if (username_exists($username) || email_exists($email)) {
        return new WP_Error('user_exists', 'User already exists.', ['status' => 409]);
    }

    $user_id = wp_create_user($username, $password, $email);
    if (is_wp_error($user_id)) {
        return new WP_Error('create_failed', $user_id->get_error_message(), ['status' => 500]);
    }

    $updated = wp_update_user(['ID' => $user_id, 'role' => $role]);
    if (is_wp_error($updated)) {
        return new WP_Error('role_failed', $updated->get_error_message(), ['status' => 500]);
    }

    return new WP_REST_Response(['status' => 'created', 'user_id' => $user_id], 201);
}

function md_control_update_user(WP_REST_Request $request) {
    $user_id = (int) $request->get_param('id');
    if (!get_userdata($user_id)) {
        return new WP_Error('user_not_found', 'User not found.', ['status' => 404]);
    }

    $data = ['ID' => $user_id];
    $password = $request->get_param('password');
    $role = sanitize_text_field($request->get_param('role'));

    if ($password) $data['user_pass'] = $password;

    $updated = wp_update_user($data);
    if (is_wp_error($updated)) {
        return new WP_Error('update_failed', $updated->get_error_message(), ['status' => 500]);
    }

    if ($role) {
        $user = new WP_User($user_id);
        $user->set_role($role);
    }

    return new WP_REST_Response(['status' => 'updated', 'user_id' => $user_id], 200);
}

function md_control_delete_user(WP_REST_Request $request) {
    $user_id = (int) $request->get_param('id');
    if (!get_userdata($user_id)) {
        return new WP_Error('user_not_found', 'User not found.', ['status' => 404]);
    }

    if (get_current_user_id() === $user_id) {
        return new WP_Error('cannot_delete_self', 'You cannot delete the current user.', ['status' => 403]);
    }

    $deleted = wp_delete_user($user_id, 1);
    if (!$deleted) {
        return new WP_Error('delete_failed', 'Could not delete user.', ['status' => 500]);
    }

    return new WP_REST_Response(['status' => 'deleted', 'user_id' => $user_id], 200);
}

function md_control_list_users(WP_REST_Request $request) {
    $role_filter = sanitize_text_field($request->get_param('role'));
    $args = $role_filter ? ['role' => $role_filter] : [];

    $users = array_map(function($user) {
        return [
            'id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'display_name' => $user->display_name,
            'role' => $user->roles[0] ?? 'unknown',
        ];
    }, get_users($args));

    return new WP_REST_Response($users, 200);
}

function md_control_trigger_backup() {
    $backup_dir = WP_CONTENT_DIR . '/ai1wm-backups';
    $cmd = 'wp ai1wm backup';

    chdir(ABSPATH);
    ob_start();
    passthru($cmd, $exitCode);
    $output = ob_get_clean();

    $backups = glob("$backup_dir/*.wpress");
    usort($backups, fn($a, $b) => filemtime($b) - filemtime($a));
    $latest = $backups[0] ?? null;

    if (!$latest || !file_exists($latest)) {
        return new WP_Error('no_backup', 'No backup file was created.', ['status' => 500]);
    }

    return new WP_REST_Response([
        'status' => 'success',
        'filename' => basename($latest),
        'path' => realpath($latest),
        'cli_output' => trim($output),
    ], 200);
}

function md_control_get_latest_backup() {
    $backups = glob(AI1WM_BACKUPS_PATH . '/*.wpress');
    usort($backups, fn($a, $b) => filemtime($b) - filemtime($a));

    if (empty($backups)) return new WP_REST_Response([], 200);

    $latest = basename($backups[0]);
    return new WP_REST_Response([
        'status' => 'found',
        'filename' => $latest,
        'path' => realpath(AI1WM_BACKUPS_PATH . '/' . $latest),
    ], 200);
}

function md_control_download_backup(WP_REST_Request $request) {
    $filename = basename($request->get_param('file'));
    $filepath = AI1WM_BACKUPS_PATH . '/' . $filename;

    if (!file_exists($filepath)) {
        return new WP_Error('file_not_found', 'Backup file does not exist.', ['status' => 404]);
    }

    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . filesize($filepath));

    readfile($filepath);
    exit;
}

function md_control_get_update_status() {
    require_once ABSPATH . 'wp-admin/includes/update.php';
    wp_version_check();
    wp_update_plugins();
    wp_update_themes();

    $plugins = get_site_transient('update_plugins');
    $themes = get_site_transient('update_themes');
    $core = get_site_transient('update_core');

    $plugin_updates = !empty($plugins->response) ? count($plugins->response) : 0;
    $theme_updates = !empty($themes->response) ? count($themes->response) : 0;
    $core_updates = 0;

    if (!empty($core->updates) && isset($core->updates[0]->response) && $core->updates[0]->response === 'upgrade') {
        $core_updates = 1;
    }

    return rest_ensure_response([
        'plugins' => $plugin_updates,
        'themes' => $theme_updates,
        'core' => $core_updates,
        'total' => $plugin_updates + $theme_updates + $core_updates,
    ]);
}