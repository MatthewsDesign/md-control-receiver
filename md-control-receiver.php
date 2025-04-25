<?php
/**
 * Plugin Name: MD Control Receiver
 * Description: Remote management receiver for MD Control.
 * Version: 1.1.9
 * Author: Matthews Design
 */

defined('ABSPATH') || exit;

register_activation_hook(__FILE__, 'md_control_generate_api_key');

function md_control_generate_api_key() {
    $option_name = 'md_control_api_key';
    if (!get_option($option_name)) {
        $api_key = bin2hex(random_bytes(16));
        add_option($option_name, $api_key, '', false);
    }
}

require_once plugin_dir_path(__FILE__) . 'includes/api/endpoints.php';
require_once plugin_dir_path(__FILE__) . 'includes/admin/settings-page.php';

add_action('init', function () {
    if (!is_admin()) return;

    new MD_GitHub_Updater(__FILE__, [
        'user'  => 'MatthewsDesign',
        'repo'  => 'md-control-receiver',
    ]);
});

class MD_GitHub_Updater {
    private $file, $slug, $user, $repo;

    public function __construct($file, $args) {
        $this->file  = $file;
        $this->slug  = plugin_basename($file);
        $this->user  = $args['user'];
        $this->repo  = $args['repo'];

        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_update']);
        add_filter('plugins_api', [$this, 'plugins_api'], 10, 3);
        add_filter('upgrader_post_install', [$this, 'after_install'], 10, 3);
    }

    private function api_request($url) {
        $headers = ['User-Agent' => 'WordPress', 'Accept' => 'application/vnd.github.v3+json'];
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
                'package'     => "https://codeload.github.com/{$this->user}/{$this->repo}/zip/{$release->tag_name}",
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
            'name'           => 'MD Control Receiver',
            'slug'           => $this->slug,
            'version'        => ltrim($release->tag_name, 'v'),
            'author'         => 'Matthews Design',
            'homepage'       => $release->html_url,
            'download_link'  => "https://codeload.github.com/{$this->user}/{$this->repo}/zip/{$release->tag_name}",
            'sections'       => [
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

add_filter('auto_update_plugin', function ($update, $item) {
    return ($item->plugin === plugin_basename(__FILE__)) ? true : $update;
}, 10, 2);
