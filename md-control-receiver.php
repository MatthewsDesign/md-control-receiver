<?php
/**
 * Plugin Name: MD Control Receiver
 * Description: Remote management receiver for MD Control.
 * Version: 1.1.1
 * Author: Matthews Design
 */

defined('ABSPATH') || exit;

// Register plugin activation hook to generate the API key and store GitHub token
register_activation_hook(__FILE__, function () {
    $option_name = 'md_control_api_key';
    if (!get_option($option_name)) {
        $api_key = bin2hex(random_bytes(16));
        add_option($option_name, $api_key, '', false);
    }

    // Store GitHub token for secure updater access (only once, on install)
    if (!get_option('md_control_github_token')) {
        add_option('md_control_github_token', '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');
    }
});

// Load REST API endpoints
require_once plugin_dir_path(__FILE__) . 'includes/api/endpoints.php';

// Load admin UI for settings page
if (is_admin()) {
    require_once plugin_dir_path(__FILE__) . 'includes/admin/settings-page.php';
}

// GitHub Updater (WordPress-native)
add_action('init', function () {
    if (!is_admin()) return;

    new MD_GitHub_Updater(__FILE__, [
        'user'  => 'MatthewsDesign',
        'repo'  => 'md-control-receiver',
        'token' => get_option('md_control_github_token'),
    ]);
});

class MD_GitHub_Updater {
    private $file, $slug, $user, $repo, $token;

    public function __construct($file, $args) {
        $this->file  = $file;
        $this->slug  = plugin_basename($file);
        $this->user  = $args['user'];
        $this->repo  = $args['repo'];
        $this->token = $args['token'];

        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_update']);
        add_filter('plugins_api', [$this, 'plugins_api'], 10, 3);
        add_filter('upgrader_post_install', [$this, 'after_install'], 10, 3);
    }

    private function api_request($url) {
        $headers = ['User-Agent' => 'WordPress', 'Accept' => 'application/vnd.github.v3+json'];
        if ($this->token) {
            $headers['Authorization'] = 'token ' . $this->token;
        }

        $response = wp_remote_get($url, ['headers' => $headers]);
        if (is_wp_error($response)) return false;

        return json_decode(wp_remote_retrieve_body($response));
    }

    public function check_update($transient) {
        if (empty($transient->checked)) return $transient;

        $release = $this->api_request("https://api.github.com/repos/{$this->user}/{$this->repo}/releases/latest");
        if (!$release || empty($release->tag_name)) return $transient;

        $plugin_data = get_plugin_data($this->file);
        $current = $plugin_data['Version'];
        $remote  = ltrim($release->tag_name, 'v');

        if (version_compare($remote, $current, '>')) {
            $transient->response[$this->slug] = (object)[
                'slug'        => dirname($this->slug),
                'plugin'      => $this->slug,
                'new_version' => $remote,
                'package'     => $release->zipball_url,
                'url'         => $release->html_url,
            ];
        }

        return $transient;
    }

    public function plugins_api($res, $action, $args) {
        if ($action !== 'plugin_information' || $args->slug !== dirname($this->slug)) return $res;

        $release = $this->api_request("https://api.github.com/repos/{$this->user}/{$this->repo}/releases/latest");
        if (!$release) return $res;

        return (object)[
            'name'        => 'MD Control Receiver',
            'slug'        => $this->slug,
            'version'     => ltrim($release->tag_name, 'v'),
            'author'      => 'Matthews Design',
            'homepage'    => $release->html_url,
            'download_link' => $release->zipball_url,
            'sections'    => [
                'description' => $release->body ?? '',
            ],
        ];
    }

    public function after_install($res, $extra, $result) {
        global $wp_filesystem;

        $slug = dirname($this->slug);
        $destination = WP_PLUGIN_DIR . '/' . $slug;
        $wp_filesystem->move($result['destination'], $destination);
        $result['destination'] = $destination;

        return $result;
    }
}
