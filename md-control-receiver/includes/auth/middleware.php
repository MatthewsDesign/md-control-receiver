<?php

/**
 * Authenticate MD Control API requests using the 'md-control-key' header.
 */
function md_control_authenticate(WP_REST_Request $request) {
    $provided_key = $request->get_header('md-control-key');
    $expected_key = get_option('md_control_api_key');

    if (function_exists('error_log')) {
        error_log("MD Control: Provided key: {$provided_key}");
        error_log("MD Control: Expected key: {$expected_key}");
    }

    if (!$expected_key) {
        return new WP_Error('missing_api_key', 'API key is not set.', ['status' => 500]);
    }

    return hash_equals($expected_key, $provided_key);
}
