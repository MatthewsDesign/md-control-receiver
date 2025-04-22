<?php
/**
 * Plugin Name: MD Control Receiver
 * Description: Remote management receiver for MD Control.
 * Version: 1.1.1
 * Author: Matthews Design
 */

defined('ABSPATH') || exit;

// Register plugin activation hook to generate the API key
register_activation_hook(__FILE__, 'md_control_generate_api_key');

function md_control_generate_api_key() {
    $option_name = 'md_control_api_key';

    if (!get_option($option_name)) {
        $api_key = bin2hex(random_bytes(16));
        add_option($option_name, $api_key, '', false);
    }
}

// Load REST API endpoints
require_once plugin_dir_path(__FILE__) . 'includes/api/endpoints.php';

// Load admin UI for settings page
if (is_admin()) {
    require_once plugin_dir_path(__FILE__) . 'includes/admin/settings-page.php';
}

add_action('admin_init', 'md_control_check_for_plugin_update');

function md_control_check_for_plugin_update() {
    $current_version = '1.0';
    $repo_owner = 'MatthewsDesign';
    $repo_name = 'md-control-receiver';
    $token = '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';
    $api_url = "https://api.github.com/repos/$repo_owner/$repo_name/releases/latest";

    $response = wp_remote_get($api_url, [
        'headers' => [
            'User-Agent' => 'WordPress Plugin Updater',
            'Authorization' => 'token ' . $token,
        ]
    ]);

    if (is_wp_error($response)) return;

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);
    if (!isset($data['tag_name'])) return;

    $latest_version = ltrim($data['tag_name'], 'v');
    if (version_compare($current_version, $latest_version, '<')) {
        md_control_update_plugin_from_github($data['zipball_url'], $token);
    }
}

function md_control_update_plugin_from_github($zip_url, $token) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/misc.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

    $response = wp_remote_get($zip_url, [
        'headers' => [
            'User-Agent' => 'WordPress Plugin Updater',
            'Authorization' => 'token ' . $token,
        ],
        'stream' => true,
        'timeout' => 300,
        'filename' => WP_TEMP_DIR . '/md-control-receiver.zip',
    ]);

    if (is_wp_error($response)) return;

    $tmp_file = wp_tempnam('md-control-receiver');
    if (!$tmp_file) return;

    file_put_contents($tmp_file, wp_remote_retrieve_body($response));
    $plugin_dir = plugin_dir_path(__FILE__);

    $result = unzip_file($tmp_file, $plugin_dir);
    unlink($tmp_file);

    if (is_wp_error($result)) {
        error_log('MD Control plugin update failed: ' . $result->get_error_message());
    }
}