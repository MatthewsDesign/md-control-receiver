<?php
/**
 * Plugin Name: MD Control Receiver
 * Description: Remote management receiver for MD Control.
 * Version: 1.0
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

// GitHub Updater (uses /releases instead of /releases/latest)
add_action('admin_init', 'md_control_check_for_plugin_update');

function md_control_check_for_plugin_update() {
    $current_version = '1.0';
    $repo_owner = 'MatthewsDesign';
    $repo_name = 'md-control-receiver';
    $token = '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'; // Replace with your token
    $api_url = "https://api.github.com/repos/$repo_owner/$repo_name/releases";

    $response = wp_remote_get($api_url, [
        'headers' => [
            'User-Agent' => 'WordPress Plugin Updater',
            'Authorization' => 'token ' . $token,
            'Accept' => 'application/vnd.github.v3+json',
        ]
    ]);

    if (is_wp_error($response)) {
        error_log('GitHub API error: ' . $response->get_error_message());
        return;
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (!is_array($data) || empty($data[0]['tag_name']) || empty($data[0]['zipball_url'])) {
        error_log('GitHub API: no valid releases found.');
        return;
    }

    $latest_version = ltrim($data[0]['tag_name'], 'v');
    $zip_url = $data[0]['zipball_url'];

    if (version_compare($current_version, $latest_version, '<')) {
        md_control_update_plugin_from_github($zip_url, $token);
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
        ]
    ]);

    if (is_wp_error($response)) {
        error_log('Plugin download failed: ' . $response->get_error_message());
        return;
    }

    $tmp_file = wp_tempnam('md-control-receiver');
    if (!$tmp_file) {
        error_log('Failed to create temp file.');
        return;
    }

    file_put_contents($tmp_file, wp_remote_retrieve_body($response));

    $plugin_dir = plugin_dir_path(__FILE__);
    $result = unzip_file($tmp_file, $plugin_dir);
    unlink($tmp_file);

    if (is_wp_error($result)) {
        error_log('MD Control plugin update failed: ' . $result->get_error_message());
    } else {
        error_log('MD Control plugin updated successfully to new version.');
    }
}
