<?php

add_action('admin_menu', 'md_control_add_settings_page');

function md_control_add_settings_page() {
    add_options_page(
        'MD Control Settings',
        'MD Control',
        'manage_options',
        'md-control-settings',
        'md_control_render_settings_page'
    );
}

function md_control_render_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $option_name = 'md_control_api_key';

    // Handle form submission and key regeneration
    if (
        isset($_POST['regenerate_md_control_key']) &&
        check_admin_referer('md_control_regenerate_key')
    ) {
        $new_key = bin2hex(random_bytes(16));
        update_option($option_name, $new_key);
        echo '<div class="updated"><p>New API key generated.</p></div>';
    }

    $api_key = get_option($option_name);
    ?>

    <div class="wrap">
        <h1>MD Control API Key</h1>
        <p>This key allows your Laravel hub to securely communicate with this site.</p>

        <form method="post">
            <?php wp_nonce_field('md_control_regenerate_key'); ?>

            <label for="md-control-key"><strong>API Key:</strong></label><br>
            <input
                type="password"
                id="md-control-key"
                value="<?php echo esc_attr($api_key); ?>"
                readonly
                style="width: 400px;"
            />
            <button type="button" onclick="toggleKey()" class="button">Show/Hide</button>

            <br><br>

            <input type="submit" name="regenerate_md_control_key" class="button button-primary" value="Regenerate API Key" />
        </form>

        <script>
            function toggleKey() {
                const input = document.getElementById('md-control-key');
                input.type = input.type === 'password' ? 'text' : 'password';
            }
        </script>
    </div>

    <?php
}
