<?php
// kill it if this gets hit from a browser
if (php_sapi_name() !== 'cli' && !defined('DOING_CRON')) {
    exit('Not allowed');
}

// run backup via WP-CLI
chdir(dirname(__FILE__, 3)); // go to WordPress root

$cmd = 'wp ai1wm backup';
shell_exec($cmd);
