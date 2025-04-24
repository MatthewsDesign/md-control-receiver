<?php

require_once plugin_dir_path(__DIR__) . 'auth/middleware.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

add_action('rest_api_init', 'md_control_register_api');

function md_control_register_api() {
    register_rest_route('md-control/v1', '/ping', [
        'methods' => 'POST',
        'callback' => 'md_control_ping',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/users', [
        'methods' => 'POST',
        'callback' => 'md_control_create_user',
        'permission_callback' => 'md_control_authenticate',
    ]);

    register_rest_route('md-control/v1', '/users/(?P<id>\d+)', [
        'methods' => 'DELETE',
        'callback' => 'md_control_delete_user',
        'permission_callback' => 'md_control_authenticate',
        'args' => [
            'id' => [
                'required' => true,
                'validate_callback' => function($value, $request, $param) {
                    return is_numeric($value);
                }
            ]
        ]
    ]);

    register_rest_route('md-control/v1', '/users/(?P<id>\d+)', [
        'methods' => 'POST',
        'callback' => 'md_control_update_user',
        'permission_callback' => 'md_control_authenticate',
        'args' => [
            'id' => [
                'required' => true,
                'validate_callback' => function($value, $request, $param) {
                    return is_numeric($value);
                }
            ]
        ]
    ]);

    register_rest_route('md-control/v1', '/users', [
        'methods' => 'GET',
        'callback' => 'md_control_list_users',
        'permission_callback' => 'md_control_authenticate',
    ]);

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
                'validate_callback' => function($value, $request, $param) {
                    return preg_match('/^[a-zA-Z0-9._-]+\.wpress$/', $value);
                }
            ]
        ]
    ]);
}


function md_control_ping(WP_REST_Request $request) {
    return [
        'status' => 'ok',
        'site_name' => get_bloginfo('name'),
        'wp_version' => get_bloginfo('version'),
        'plugin_version' => '1.0',
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

    $updated = wp_update_user([
        'ID' => $user_id,
        'role' => $role
    ]);

    if (is_wp_error($updated)) {
        return new WP_Error('role_failed', $updated->get_error_message(), ['status' => 500]);
    }

    return new WP_REST_Response([
        'status' => 'created',
        'user_id' => $user_id
    ], 201);
}

function md_control_delete_user(WP_REST_Request $request) {
    $user_id = (int) $request->get_param('id');

    if (!function_exists('wp_delete_user')) {
        if (function_exists('error_log')) {
            error_log('wp_delete_user does not exist, trying to require it.');
        }
        require_once ABSPATH . 'wp-admin/includes/user.php';
    }

    if (!get_userdata($user_id)) {
        if (function_exists('error_log')) {
            error_log("User $user_id not found.");
        }
        return new WP_Error('user_not_found', 'User not found.', ['status' => 404]);
    }

    if (get_current_user_id() === $user_id) {
        if (function_exists('error_log')) {
            error_log("Attempted to delete current user $user_id.");
        }
        return new WP_Error('cannot_delete_self', 'You cannot delete the current user.', ['status' => 403]);
    }

    if (function_exists('error_log')) {
        error_log("Attempting to delete user $user_id with reassignment to ID 1.");
    }

    $deleted = wp_delete_user($user_id, 1);

    if (!$deleted) {
        error_log("wp_delete_user returned false or null for user $user_id.");
        return new WP_Error('delete_failed', 'Could not delete user.', ['status' => 500]);
    }

    error_log("User $user_id successfully deleted.");

    return new WP_REST_Response([
        'status' => 'deleted',
        'user_id' => $user_id
    ], 200);
}



function md_control_update_user(WP_REST_Request $request) {
    $user_id = (int) $request->get_param('id');

    if (!get_userdata($user_id)) {
        return new WP_Error('user_not_found', 'User not found.', ['status' => 404]);
    }

    $data = ['ID' => $user_id];

    $password = $request->get_param('password');
    $role = sanitize_text_field($request->get_param('role'));

    if ($password) {
        $data['user_pass'] = $password;
    }

    $updated = wp_update_user($data);

    if (is_wp_error($updated)) {
        return new WP_Error('update_failed', $updated->get_error_message(), ['status' => 500]);
    }

    if ($role) {
        $user = new WP_User($user_id);
        $user->set_role($role);
    }

    return new WP_REST_Response([
        'status' => 'updated',
        'user_id' => $user_id
    ], 200);
}

function md_control_list_users(WP_REST_Request $request) {
    $role_filter = sanitize_text_field($request->get_param('role'));

    $args = [];
    if ($role_filter) {
        $args['role'] = $role_filter;
    }

    // Fetch full user objects to ensure roles are available
    $wp_users = get_users($args);
    $users = [];

    foreach ($wp_users as $user) {
        $users[] = [
            'id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'display_name' => $user->display_name,
            'role' => isset($user->roles[0]) ? $user->roles[0] : 'unknown'
        ];
    }

    return new WP_REST_Response($users, 200);
}


function md_control_trigger_backup(WP_REST_Request $request) {
    $wp_root = ABSPATH;
    $backup_dir = WP_CONTENT_DIR . '/ai1wm-backups';

    // Build command
    $cmd = 'wp ai1wm backup';

    // Try safest available method
    if (function_exists('passthru')) {
        chdir($wp_root);
        ob_start();
        passthru($cmd, $exitCode);
        $output = ob_get_clean();
    } elseif (function_exists('exec')) {
        chdir($wp_root);
        exec($cmd . ' 2>&1', $outputLines, $exitCode);
        $output = implode("\n", $outputLines);
    } else {
        return new WP_Error('disabled_functions', 'All safe CLI execution functions are disabled.', ['status' => 500]);
    }

    // Check for backup file
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

function md_control_get_latest_backup(WP_REST_Request $request) {
    if (!defined('AI1WM_BACKUPS_PATH')) {
        return new WP_Error('ai1wm_missing', 'Backup path not found.', ['status' => 500]);
    }

    $backups = glob(AI1WM_BACKUPS_PATH . '/*.wpress');
    usort($backups, function ($a, $b) {
        return filemtime($b) - filemtime($a);
    });

    if (empty($backups)) {
        return new WP_REST_Response([], 200);
    }

    $latest = basename($backups[0]);
    $absolute_path = realpath(AI1WM_BACKUPS_PATH . '/' . $latest);

    return new WP_REST_Response([
        'status' => 'found',
        'filename' => $latest,
        'path' => $absolute_path,
    ], 200);
}

add_action('init', function () {
    if (!isset($_GET['user'], $_GET['expires'], $_GET['sig'])) {
        return;
    }

    // Only run on wp-login.php
    if (!str_contains($_SERVER['REQUEST_URI'], 'wp-login.php')) {
        return;
    }

    $email = sanitize_email($_GET['user']);
    $expires = intval($_GET['expires']);
    $sig = sanitize_text_field($_GET['sig']);

    // Check expiration (within 10 mins)
    if (time() > $expires) {
        wp_die('Login link expired.');
    }

    // Load secret from saved option
    $secret = get_option('md_control_api_key');
    $payload = "user=$email&expires=$expires";
    $expected = hash_hmac('sha256', $payload, $secret);

    if (!hash_equals($expected, $sig)) {
        wp_die('Invalid signature.');
    }

    $user = get_user_by('email', $email);

    if (!$user) {
        wp_die('User not found.');
    }

    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID);
    wp_redirect(admin_url());
    exit;
});
