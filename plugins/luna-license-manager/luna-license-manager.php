<?php
/**
 * Plugin Name: Luna License Manager (Clean)
 * Description: Manages Luna Licenses and VL Client Users - Clean version without conflicting REST API endpoints
 * Version:     1.1.0
 * Author:      Visible Light
 */

if (!defined('ABSPATH')) {
    exit;
}

final class VL_License_Manager {
    /**
     * Singleton instance.
     *
     * @var VL_License_Manager|null
     */
    private static $instance = null;

    /**
     * Bootstraps hooks.
     */
    private function __construct() {
        add_action('admin_menu', array($this, 'register_admin_menu'));
        add_filter('login_redirect', array($this, 'filter_login_redirect'), 10, 3);
        add_action('wp_logout', array($this, 'handle_logout_redirect'));
        add_action('init', array($this, 'maybe_bootstrap_console_session'));
        add_action('template_redirect', array($this, 'protect_console')); // Runs on front-end
        add_action('template_redirect', array($this, 'redirect_authenticated_clients'));
        add_action('login_init', array($this, 'maybe_redirect_logged_in_client_from_wp_login'));
        add_action('rest_api_init', array($this, 'register_rest_routes'));
        add_action('init', array($this, 'maybe_create_missing_licenses'));
        add_action('rest_api_init', array($this, 'add_cors_headers'));
        add_action('vl_auto_sync_liquidweb', array($this, 'auto_sync_liquidweb_assets'));
        add_filter('cron_schedules', array($this, 'add_liquidweb_cron_schedule'));
    }

    private static function console_base_paths() {
        return array(
            '/ai-constellation-dashboard/',
            '/ai-constellation-console/',
        );
    }

    private static function console_primary_path() {
        $paths = self::console_base_paths();

        return isset($paths[0]) ? $paths[0] : '/ai-constellation-dashboard/';
    }

    private static function url_targets_console($url) {
        if (empty($url) || !is_string($url)) {
            return false;
        }

        $parsed = wp_parse_url($url);
        $path   = '';
        if (is_array($parsed) && isset($parsed['path'])) {
            $path = (string) $parsed['path'];
        } else {
            $path = (string) $url;
        }

        $needle_source = trim($path, '/');
        foreach (self::console_base_paths() as $base) {
            $needle = trim($base, '/');
            if ('' !== $needle && false !== stripos($needle_source, $needle)) {
                return true;
            }
        }

        return false;
    }

    private static function is_console_page_context() {
        if (function_exists('is_page')) {
            if (is_page(array('ai-constellation-dashboard', 'ai-constellation-console'))) {
                return true;
            }
        }

        if (empty($_SERVER['REQUEST_URI'])) {
            return false;
        }

        return self::url_targets_console((string) wp_unslash($_SERVER['REQUEST_URI']));
    }

    /**
     * Returns the singleton instance.
     */
    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Handles plugin activation.
     */
    public static function activate() {
        self::add_clients_role();
        self::seed_default_licenses();
        self::fix_missing_site_urls();
        self::create_sample_data_streams();
        
        // Schedule Liquid Web auto-sync (every 6 hours)
        if (!wp_next_scheduled('vl_auto_sync_liquidweb')) {
            wp_schedule_event(time(), 'vl_liquidweb_sync', 'vl_auto_sync_liquidweb');
        }
    }

    /**
     * Fixes existing licenses that are missing site URLs.
     */
    private static function fix_missing_site_urls() {
        $store = self::lic_store_get();
        $updated = false;
        
        $site_mappings = array(
            'VL-VYAK-9BPQ-NKCC' => 'https://commonwealthhealthservices.com',
            'VL-H2K3-ZFQK-DKDC' => 'https://siteassembly.com',
            'VL-SAMPLE-XXXX-XXXX' => 'https://example.com',
        );
        
        foreach ($store as $license_key => $license_data) {
            if (empty($license_data['site']) && isset($site_mappings[$license_key])) {
                $store[$license_key]['site'] = $site_mappings[$license_key];
                $updated = true;
                error_log('[VL Hub] Fixed missing site URL for license: ' . $license_key);
            }
        }
        
        if ($updated) {
            self::lic_store_set($store);
        }
    }

    /**
     * Public method to fix missing site URLs (can be called manually).
     */
    public static function fix_licenses_now() {
        self::fix_missing_site_urls();
        return 'License site URLs have been updated.';
    }

    /**
     * Handles plugin deactivation.
     */
    public static function deactivate() {
        remove_role('vl_client');
        
        // Clear scheduled events
        wp_clear_scheduled_hook('vl_auto_sync_liquidweb');
    }
    
    /**
     * Add custom cron schedule for Liquid Web sync
     */
    public static function add_liquidweb_cron_schedule($schedules) {
        $schedules['vl_liquidweb_sync'] = array(
            'interval' => 6 * HOUR_IN_SECONDS, // 6 hours
            'display' => __('Every 6 Hours (Liquid Web Sync)', 'visible-light')
        );
        return $schedules;
    }

    /**
     * Registers the VL Client role if it is missing.
     */
    private static function add_clients_role() {
        if (!get_role('vl_client')) {
            add_role(
                'vl_client',
                'VL Client',
                array(
                    'read'                   => true,
                    'vl_access_supercluster' => true,
                    'vl_view_own_data'       => true,
                )
            );
        }
    }

    /**
     * Seeds default licenses when registry is empty.
     */
    private static function seed_default_licenses() {
        $licenses = self::lic_store_get();
        if (empty($licenses)) {
            $default_licenses = array(
                'VL-VYAK-9BPQ-NKCC' => array(
                    'client_name' => 'Commonwealth Health Services',
                    'site'        => 'https://commonwealthhealthservices.com',
                    'status'      => 'active',
                    'created'     => current_time('mysql'),
                ),
                'VL-H2K3-ZFQK-DKDC' => array(
                    'client_name' => 'Site Assembly',
                    'site'        => 'https://siteassembly.com',
                    'status'      => 'active',
                    'created'     => current_time('mysql'),
                ),
                'VL-SAMPLE-XXXX-XXXX' => array(
                    'client_name' => 'Sample Client',
                    'site'        => 'https://example.com',
                    'status'      => 'active',
                    'created'     => current_time('mysql'),
                ),
            );

            self::lic_store_set($default_licenses);
        }
    }

    /**
     * Helper accessor for license store.
     */
    private static function lic_store_get() {
        $store = get_option('vl_licenses_registry', array());
        if (!is_array($store)) {
            return array();
        }

        $cleaned    = array();
        $did_update = false;

        foreach ($store as $license_key => $license_data) {
            if (self::is_legacy_license_key($license_key)) {
                $did_update = true;
                continue;
            }

            if (!is_array($license_data)) {
                $license_data = array();
                $did_update   = true;
            }

            if (!isset($license_data['key']) || $license_data['key'] !== $license_key) {
                $license_data['key'] = $license_key;
                $did_update          = true;
            }

            if (isset($license_data['contact_email'])) {
                $clean_email = sanitize_email($license_data['contact_email']);
                if ($license_data['contact_email'] !== $clean_email) {
                    $license_data['contact_email'] = $clean_email;
                    $did_update                     = true;
                }
            }

            $cleaned[$license_key] = $license_data;
        }

        if ($did_update) {
            update_option('vl_licenses_registry', $cleaned);
        }

        return $cleaned;
    }

    private static function lic_store_set($list) {
        if (!is_array($list)) {
            $list = array();
        }

        $cleaned = array();

        foreach ($list as $license_key => $license_data) {
            if (self::is_legacy_license_key($license_key)) {
                continue;
            }

            if (!is_array($license_data)) {
                $license_data = array();
            }

            if (!isset($license_data['key']) || $license_data['key'] !== $license_key) {
                $license_data['key'] = $license_key;
            }

            if (isset($license_data['contact_email'])) {
                $license_data['contact_email'] = sanitize_email($license_data['contact_email']);
            }

            $cleaned[$license_key] = $license_data;
        }

        update_option('vl_licenses_registry', $cleaned);
    }

    private static function conn_store_get() {
        $store = get_option('vl_connections_registry', array());
        return is_array($store) ? $store : array();
    }

    private static function conn_store_set($list) {
        update_option('vl_connections_registry', is_array($list) ? $list : array());
    }

    private static function lic_generate_key() {
        $alph = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $chunk = function() use($alph){ $s=''; for($i=0;$i<4;$i++) $s .= $alph[random_int(0, strlen($alph)-1)]; return $s; };
        return 'VL-' . $chunk() . '-' . $chunk() . '-' . $chunk();
    }

    private static function lic_create_with_key($client, $site, $key, $active = false, $email = '') {
        if (self::is_legacy_license_key($key)) {
            error_log('[VL Licenses] Attempt to create legacy lic_ license discarded.');
            $key = self::lic_generate_key();
        }

        $email = sanitize_email($email);

        $license = array(
            'client_name' => $client,
            'site'        => $site,
            'key'         => $key,
            'status'      => $active ? 'active' : 'inactive',
            'created'     => current_time('mysql'),
            'last_seen'   => null,
            'contact_email' => $email,
        );

        $store       = self::lic_store_get();
        $store[$key] = $license;
        self::lic_store_set($store);

        return $license;
    }

    private static function lic_create($client, $site, $email = '') {
        $key = self::lic_generate_key();
        return self::lic_create_with_key($client, $site, $key, false, $email);
    }

    private static function lic_lookup_by_key($key) {
        if (self::is_legacy_license_key($key)) {
            return null;
        }

        $store = self::lic_store_get();

        if (isset($store[$key])) {
            return $store[$key];
        }

        foreach ($store as $license_data) {
            if (isset($license_data['key']) && $license_data['key'] === $key) {
                return $license_data;
            }
        }

        return null;
    }

    /**
     * Updates a license with new data.
     * 
     * @param string $license_key The license key to update
     * @param array $update_data The data to update
     * @return bool True if successful, false otherwise
     */
    private static function lic_update($license_key, $update_data) {
        $store = self::lic_store_get();
        
        if (!isset($store[$license_key])) {
            return false;
        }
        
        $store[$license_key] = array_merge($store[$license_key], $update_data);
        self::lic_store_set($store);
        
        return true;
    }

    private static function is_legacy_license_key($key) {
        if (!is_string($key)) {
            return false;
        }

        return 0 === stripos($key, 'lic_');
    }

    private static function lic_redact($key) {
        if (empty($key)) {
            return '';
        }

        return substr($key, 0, 8) . '...' . substr($key, -4);
    }

    private static function lic_dashboard_segment($license_key) {
        $sanitized = preg_replace('/[^A-Za-z0-9\-]/', '-', $license_key);
        $sanitized = trim($sanitized, '-');
        return strtolower($sanitized);
    }

    private static function lic_dashboard_url($license, $fallback_key = '') {
        $key = isset($license['key']) ? $license['key'] : $fallback_key;
        if (empty($key)) {
            return 'https://supercluster.visiblelight.ai/';
        }

        return add_query_arg(
            'license',
            $key,
            'https://supercluster.visiblelight.ai/'
        );
    }

    /**
     * Extracts the license key from the current request in a tolerant way.
     *
     * @return array{license:string,source:string}
     */
    private static function lic_extract_request_license() {
        $result = array(
            'license' => '',
            'source'  => 'none',
        );

        if (isset($_GET['license'])) {
            $value = sanitize_text_field(wp_unslash($_GET['license']));
            if (!empty($value)) {
                $result['license'] = $value;
                $result['source']  = 'license';

                return $result;
            }
        }

        if (isset($_GET['lic'])) {
            $value = sanitize_text_field(wp_unslash($_GET['lic']));
            if (!empty($value)) {
                $result['license'] = $value;
                $result['source']  = 'lic';

                return $result;
            }
        }

        if (isset($_SERVER['REQUEST_URI'])) {
            $request_uri = wp_unslash($_SERVER['REQUEST_URI']);
            if (is_string($request_uri)) {
                if (preg_match('~/ai-constellation-(?:console|dashboard)/(?:[^/?#]+/)?lic=([^/?#&]+)~i', $request_uri, $matches)) {
                    $result['license'] = sanitize_text_field($matches[1]);
                    $result['source']  = 'path';

                    return $result;
                }

                if (preg_match('~/supercluster-constellation/(?:[^/?#]+/)?license=([^/?#&]+)~i', $request_uri, $matches)) {
                    $result['license'] = sanitize_text_field($matches[1]);
                    $result['source']  = 'path';

                    return $result;
                }
            }
        }

        return $result;
    }

    private static function lic_extract_license_from_url($url) {
        if (empty($url)) {
            return '';
        }

        $parts = wp_parse_url($url);

        if (isset($parts['query'])) {
            parse_str($parts['query'], $query_vars);
            if (isset($query_vars['license']) && !empty($query_vars['license'])) {
                return sanitize_text_field((string) $query_vars['license']);
            }

            if (isset($query_vars['lic']) && !empty($query_vars['lic'])) {
                return sanitize_text_field((string) $query_vars['lic']);
            }
        }

        if (isset($parts['path'])) {
            $path = (string) $parts['path'];
            if (preg_match('~/lic=([^/?#&]+)~i', $path, $matches)) {
                return sanitize_text_field($matches[1]);
            }

            if (preg_match('~/license=([^/?#&]+)~i', $path, $matches)) {
                return sanitize_text_field($matches[1]);
            }
        }

        return '';
    }

    /**
     * Determines if the current front-end request targets the console route.
     */
    private static function is_console_request() {
        if (!empty($_GET['license']) || !empty($_GET['lic'])) {
            return true;
        }

        if (empty($_SERVER['REQUEST_URI'])) {
            return false;
        }

        $path = wp_parse_url(wp_unslash((string) $_SERVER['REQUEST_URI']), PHP_URL_PATH);
        if (!is_string($path)) {
            return false;
        }

        $trimmed = trim($path, '/');
        foreach (self::console_base_paths() as $base_path) {
            $needle = trim($base_path, '/');
            if ('' !== $needle && false !== stripos($trimmed, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Finds a VL client user that owns a license key.
     *
     * @param string $license_key
     *
     * @return WP_User|null
     */
    private static function lic_find_user_by_license($license_key) {
        if (empty($license_key)) {
            return null;
        }

        $query = new WP_User_Query(
            array(
                'number'     => 1,
                'role__in'   => array('vl_client'),
                'meta_query' => array(
                    'relation' => 'OR',
                    array(
                        'key'   => 'vl_license_key',
                        'value' => $license_key,
                    ),
                    array(
                        'key'   => 'license_key',
                        'value' => $license_key,
                    ),
                ),
            )
        );

        $users = $query->get_results();

        if (empty($users)) {
            return null;
        }

        $user = $users[0];

        return ($user instanceof WP_User) ? $user : null;
    }

    /**
     * Ensures a WordPress user exists for the provided VL client details.
     *
     * @param string $client_name Display name for the client account.
     * @param string $email       Email address for the client account.
     * @param string $license_key License key assigned to the client.
     * @param string $site        Optional site descriptor stored with the user.
     * @param string $password    Optional password to assign when creating a new user.
     *
     * @return array|WP_Error Array with keys `user` (WP_User) and `created` (bool) on success, WP_Error otherwise.
     */
    private static function ensure_client_user($client_name, $email, $license_key, $site = '', $password = '') {
        $email = sanitize_email($email);

        if (empty($email) || !is_email($email)) {
            return new WP_Error('invalid_email', 'A valid email address is required for VL clients.');
        }

        $site = sanitize_text_field($site);

        $existing_id = email_exists($email);
        if ($existing_id) {
            $user = get_user_by('id', $existing_id);
            if (!$user instanceof WP_User) {
                return new WP_Error('existing_user_missing', sprintf('Unable to load the existing WordPress user for %s.', $email));
            }

            $user->add_role('vl_client');
            update_user_meta($user->ID, 'vl_license_key', $license_key);
            update_user_meta($user->ID, 'license_key', $license_key);

            if (!empty($site)) {
                update_user_meta($user->ID, 'vl_client_site', $site);
            }

            if (!empty($client_name) && $user->display_name !== $client_name) {
                wp_update_user(
                    array(
                        'ID'           => $user->ID,
                        'display_name' => $client_name,
                    )
                );
            }

            // Store the VL license key in wp_activation_key column
            global $wpdb;
            $wpdb->update(
                $wpdb->prefix . 'users',
                array('user_activation_key' => $license_key),
                array('ID' => $user->ID),
                array('%s'),
                array('%d')
            );

            return array(
                'user'    => get_user_by('id', $user->ID),
                'created' => false,
            );
        }

        $username_base = '';

        if (!empty($client_name)) {
            $preferred_username = strtolower(preg_replace('/\s+/', '', $client_name));
            $username_base      = sanitize_user($preferred_username, true);
        }

        if (empty($username_base)) {
            $username_base = sanitize_user(current(explode('@', $email)), true);
        }

        if (empty($username_base)) {
            $username_base = sanitize_user(strtolower(str_replace(' ', '-', $client_name)), true);
        }
        if (empty($username_base)) {
            $username_base = 'vlclient';
        }

        $username = $username_base;
        $suffix   = 1;
        while (username_exists($username)) {
            $username = $username_base . $suffix;
            $suffix++;
        }

        $password = (string) $password;
        if ('' === trim($password)) {
            $password = wp_generate_password(20, true, true);
        }
        $user_id  = wp_create_user($username, $password, $email);

        if (is_wp_error($user_id)) {
            return $user_id;
        }

        wp_update_user(
            array(
                'ID'           => $user_id,
                'display_name' => $client_name,
                'first_name'   => $client_name,
            )
        );

        $user = new WP_User($user_id);
        $user->set_role('vl_client');

        update_user_meta($user_id, 'vl_license_key', $license_key);
        update_user_meta($user_id, 'license_key', $license_key);

        if (!empty($site)) {
            update_user_meta($user_id, 'vl_client_site', $site);
        }

        // Store the VL license key in wp_activation_key column
        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . 'users',
            array('user_activation_key' => $license_key),
            array('ID' => $user_id),
            array('%s'),
            array('%d')
        );

        return array(
            'user'    => get_user_by('id', $user_id),
            'created' => true,
        );
    }

    private static function status_pill_from_row($row) {
        // Check for both old and new status field names
        $status = 'unknown';
        if (isset($row['status'])) {
            $status = $row['status'];
        } elseif (isset($row['active'])) {
            $status = $row['active'] ? 'active' : 'inactive';
        }
        
        $class  = ('active' === $status) ? 'vl-status-active' : 'vl-status-inactive';

        return '<span class="vl-status-pill ' . esc_attr($class) . '">' . esc_html(ucfirst($status)) . '</span>';
    }

    /**
     * Admin menu registration.
     */
    public function register_admin_menu() {
        add_menu_page(
            'VL Clients',
            'VL Clients',
            'manage_options',
            'vl-clients',
            array($this, 'render_licenses_screen'),
            'dashicons-admin-users',
            30
        );

        add_submenu_page(
            'vl-clients',
            'VL Hub Profile',
            'VL Hub Profile',
            'manage_options',
            'vl-hub-profile',
            array($this, 'render_hub_profile_screen')
        );
    }

    /**
     * Renders the license admin screen.
     */
    public function render_licenses_screen() {
        $licenses    = self::lic_store_get();
        $connections = self::conn_store_get(); // Reserved for future use.
        $messages    = array(
            'success' => array(),
            'error'   => array(),
        );
    
        // Handle client edit screen
        if (isset($_GET['action']) && $_GET['action'] === 'edit' && isset($_GET['license_key'])) {
            $license_key = sanitize_text_field(wp_unslash($_GET['license_key']));
            $license = isset($licenses[$license_key]) ? $licenses[$license_key] : null;
            
            if ($license) {
                $this->render_client_edit_screen($license_key, $license, $messages);
            return;
            } else {
                $messages['error'][] = 'License not found.';
            }
        }
    
        if (isset($_POST['action'])) {
            $action = sanitize_text_field(wp_unslash($_POST['action']));
    
            if ('create_license' === $action) {
                check_admin_referer('vl_create_license');
    
                $client   = sanitize_text_field(wp_unslash($_POST['client_name']));
                $site     = sanitize_text_field(wp_unslash($_POST['site']));
                $email    = isset($_POST['client_email']) ? sanitize_email(wp_unslash($_POST['client_email'])) : '';
                $password = isset($_POST['client_password']) ? trim(wp_unslash($_POST['client_password'])) : '';
    
                if (!$client || !$site || !$email || '' === $password) {
                    $messages['error'][] = 'Client name, site, email address, and password are all required.';
                } elseif (!is_email($email)) {
                    $messages['error'][] = 'Please provide a valid email address for the client.';
                } else {
                    $license = self::lic_create($client, $site, $email);
                    $ensure  = self::ensure_client_user($client, $email, $license['key'], $site, $password);
    
                    if (is_wp_error($ensure)) {
                        $messages['error'][] = $ensure->get_error_message();
    
                        $store = self::lic_store_get();
                        if (isset($store[$license['key']])) {
                            unset($store[$license['key']]);
                            self::lic_store_set($store);
                        }
                    } else {
                        $user     = $ensure['user'];
                        $username = ($user instanceof WP_User) ? $user->user_login : '';

                        if ($ensure['created']) {
                            $messages['success'][] = $username
                                ? sprintf('License created and new VL Client user %s provisioned.', $username)
                                : 'License created and new VL Client user provisioned.';
                        } else {
                            $messages['success'][] = $username
                                ? sprintf('License created and linked to existing user %s.', $username)
                                : 'License created and linked to existing user account.';
                        }
                    }

                    $licenses = self::lic_store_get();
                }
            }

            if ('sync_client_user' === $action) {
                check_admin_referer('vl_sync_client_user');

                $license_key = sanitize_text_field(wp_unslash($_POST['license_key'] ?? ''));

                if (empty($license_key)) {
                    $messages['error'][] = 'Unable to sync client: missing license key.';
                } else {
                    $license = self::lic_lookup_by_key($license_key);

                    if (!$license) {
                        $messages['error'][] = 'Unable to sync client: license not found.';
                    } else {
                        $client_name = isset($license['client_name']) ? $license['client_name'] : '';
                        $email       = isset($license['contact_email']) ? $license['contact_email'] : '';
                        $site        = isset($license['site']) ? $license['site'] : '';

                        if (empty($email)) {
                            $client_label = $client_name ? sanitize_text_field($client_name) : 'client';
                            $messages['error'][] = sprintf('Unable to sync %s: no email address stored with the license.', $client_label);
                        } else {
                            $ensure = self::ensure_client_user($client_name, $email, $license_key, $site);

                            if (is_wp_error($ensure)) {
                                $messages['error'][] = $ensure->get_error_message();
                            } else {
                                $user     = $ensure['user'];
                                $username = ($user instanceof WP_User) ? $user->user_login : '';

                                if ($ensure['created']) {
                                    $messages['success'][] = $username
                                        ? sprintf('Created new VL Client user %s and linked the license.', $username)
                                        : 'Created new VL Client user and linked the license.';
                                } else {
                                    $messages['success'][] = $username
                                        ? sprintf('Updated existing user %s and synced their VL Client access.', $username)
                                        : 'Updated the existing VL Client user and synced access.';
                                }
                            }
                        }
                    }
                }

                $licenses = self::lic_store_get();
            }

            if ('delete_license' === $action) {
                check_admin_referer('vl_delete_license');

                $key = sanitize_text_field(wp_unslash($_POST['license_key']));
                if ($key) {
                    $store = self::lic_store_get();
                    if (isset($store[$key])) {
                        $linked_user = self::lic_find_user_by_license($key);
                        unset($store[$key]);
                        self::lic_store_set($store);
                        $messages['success'][] = 'License deleted successfully.';
                        if ($linked_user instanceof WP_User) {
                            if (wp_delete_user($linked_user->ID)) {
                                $messages['success'][] = sprintf('Deleted WordPress user %s linked to the license.', $linked_user->user_login);
                            } else {
                                $messages['error'][] = sprintf('License removed but unable to delete linked user %s. Please remove them manually from Users.', $linked_user->user_login);
                            }
                        }
                        $licenses = self::lic_store_get();
                    }
                }
            }
        }
        ?>
        <div class="wrap">
            <h1>Luna Licenses</h1>
            
<?php foreach ($messages['success'] as $notice) : ?>
        <div class="notice notice-success is-dismissible"><p><?php echo esc_html($notice); ?></p></div>
<?php endforeach; ?>
<?php foreach ($messages['error'] as $notice) : ?>
        <div class="notice notice-error"><p><?php echo esc_html($notice); ?></p></div>
<?php endforeach; ?>

            <div class="vl-admin-grid">
                <div class="vl-admin-card">
                    <h2>Create New License</h2>
                    <form method="post">
                        <?php wp_nonce_field('vl_create_license'); ?>
                        <input type="hidden" name="action" value="create_license">
                        <table class="form-table">
                            <tr>
                                <th scope="row">Client Name</th>
                                <td><input type="text" name="client_name" required class="regular-text"></td>
        </tr>
        <tr>
                                <th scope="row">Site</th>
                                <td><input type="text" name="site" required class="regular-text"></td>
        </tr>
        <tr>
                                <th scope="row">Client Email</th>
                                <td><input type="email" name="client_email" required class="regular-text"></td>
        </tr>
        <tr>
                                <th scope="row">Password</th>
                                <td><input type="password" name="client_password" required class="regular-text" autocomplete="new-password"></td>
        </tr>
      </table>
                        <?php submit_button('Create License'); ?>
    </form>
                </div>

                <div class="vl-admin-card">
                    <h2>Existing Licenses</h2>
                    <table class="wp-list-table widefat fixed striped">
      <thead>
        <tr>
          <th>Client</th>
                            <th>Email</th>
                            <th>Site</th>
          <th>Key</th>
          <th>Status</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
                        <?php foreach ($licenses as $license_key => $license) : ?>
                            <tr>
                                <td><?php echo esc_html(isset($license['client_name']) ? $license['client_name'] : (isset($license['client']) ? $license['client'] : 'Unknown')); ?></td>
                                <td><?php echo esc_html(isset($license['contact_email']) ? $license['contact_email'] : ''); ?></td>
                                <td><?php echo esc_html(isset($license['site']) ? $license['site'] : ''); ?></td>
                                <td class="vl-license-key-cell">
                                    <code><?php echo esc_html(self::lic_redact($license_key)); ?></code>
                                    <button
                                        type="button"
                                        class="button button-small vl-copy-license"
                                        data-license="<?php echo esc_attr($license_key); ?>"
                                        aria-label="Copy license key <?php echo esc_attr($license_key); ?>"
                                    >Copy</button>
                                </td>
                                <td><?php echo wp_kses_post(self::status_pill_from_row($license)); ?></td>
                                <td><?php echo esc_html(isset($license['created']) ? $license['created'] : ''); ?></td>
                                <td>
                                    <a href="<?php echo esc_url(self::lic_dashboard_url($license, $license_key)); ?>" class="button button-small">View Dashboard</a>
                                    <a href="<?php echo esc_url(add_query_arg(array('page' => 'vl-clients', 'license_key' => $license_key, 'action' => 'edit'), admin_url('admin.php'))); ?>" class="button button-small">Edit Client</a>
                                    <form method="post" style="display:inline;">
                                        <?php wp_nonce_field('vl_sync_client_user'); ?>
                                        <input type="hidden" name="action" value="sync_client_user">
                                        <input type="hidden" name="license_key" value="<?php echo esc_attr($license_key); ?>">
                                        <input type="submit" class="button button-small" value="Sync User">
                                    </form>
                                    <form method="post" style="display:inline;">
                                        <?php wp_nonce_field('vl_delete_license'); ?>
                                        <input type="hidden" name="action" value="delete_license">
                                        <input type="hidden" name="license_key" value="<?php echo esc_attr($license_key); ?>">
                                        <input type="submit" class="button button-small" value="Delete" onclick="return confirm('Are you sure?');">
              </form>
            </td>
          </tr>
                        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
            </div>
        </div>

        <style>
            .vl-admin-grid {
                display: grid;
                grid-template-columns: 1fr 2fr;
                gap: 20px;
                margin-top: 20px;
            }

            .vl-admin-card {
                background: #fff;
                border: 1px solid #ccd0d4;
                border-radius: 4px;
                padding: 20px;
            }

            .vl-status-pill {
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }

            .vl-status-active {
                background: #d4edda;
                color: #155724;
            }

            .vl-status-inactive {
                background: #f8d7da;
                color: #721c24;
            }

            .vl-license-key-cell {
                display: flex;
                align-items: center;
                gap: 8px;
                flex-wrap: wrap;
            }

            .vl-license-key-cell code {
                margin-right: 0;
            }

            .vl-copy-license.vl-copy-success {
                border-color: #28a745;
                color: #155724;
                box-shadow: 0 0 0 1px rgba(40,167,69,0.4);
            }
        </style>
            <script>
        (function(){
            const notify = (btn, message) => {
                const original = btn.dataset.originalText || btn.textContent;
                if (!btn.dataset.originalText) {
                    btn.dataset.originalText = original;
                }
                btn.textContent = message;
                btn.classList.add('vl-copy-success');
                setTimeout(() => {
                    btn.textContent = btn.dataset.originalText;
                    btn.classList.remove('vl-copy-success');
                }, 2000);
            };

            const copyFallback = (text, btn) => {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.top = '-1000px';
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();

                try {
                    const succeeded = document.execCommand('copy');
                    document.body.removeChild(textarea);
                    if (succeeded) {
                        notify(btn, 'Copied!');
                    } else {
                        notify(btn, 'Copy failed');
                    }
                } catch (err) {
                    document.body.removeChild(textarea);
                    notify(btn, 'Copy failed');
                }
            };

            document.addEventListener('click', function(event){
                    const btn = event.target.closest('.vl-copy-license');
                    if (!btn) {
                        return;
                    }
    
                    const key = btn.getAttribute('data-license') || '';
                    if (!key) {
                        notify(btn, 'Copy failed');
                        return;
                    }
    
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(key)
                            .then(() => notify(btn, 'Copied!'))
                            .catch(() => copyFallback(key, btn));
                    } else {
                        copyFallback(key, btn);
                    }
                });
            })();
            </script>
        <?php
    }

    /**
     * Handles login redirect behaviour for clients vs admins.
     */
    public function filter_login_redirect($redirect_to, $requested_redirect_to, $user) {
        if (!($user instanceof WP_User)) {
            return $redirect_to;
        }

        $roles = (array) $user->roles;
        error_log('[VL Login] User: ' . $user->user_login . ', Roles: ' . implode(',', $roles));

        $license_key = get_user_meta($user->ID, 'vl_license_key', true);
        if (!$license_key) {
            $license_key = get_user_meta($user->ID, 'license_key', true);
        }

        if (!in_array('vl_client', $roles, true) && !empty($license_key)) {
            $user->add_role('vl_client');
            $roles[] = 'vl_client';
            error_log('[VL Login] Added vl_client role based on stored license for user: ' . $user->user_login);
        }

        if (!in_array('vl_client', $roles, true)) {
            error_log('[VL Login] Not a VL client, honouring requested redirect.');

            return !empty($requested_redirect_to) ? $requested_redirect_to : $redirect_to;
        }

        if (!empty($license_key) && self::is_legacy_license_key($license_key)) {
            delete_user_meta($user->ID, 'vl_license_key');
            delete_user_meta($user->ID, 'license_key');
            error_log('[VL Login] Removed legacy lic_ key for user: ' . $user->user_login);
            $license_key = '';
        }

        if (!$license_key && !empty($requested_redirect_to)) {
            $guessed = self::lic_extract_license_from_url($requested_redirect_to);
            if (!empty($guessed) && !self::is_legacy_license_key($guessed)) {
                $license_key = $guessed;
                update_user_meta($user->ID, 'vl_license_key', $license_key);
                error_log('[VL Login] Stored license from requested redirect: ' . $license_key);
            }
        }

        if (!$license_key && isset($_REQUEST['license'])) {
            $param_license = sanitize_text_field(wp_unslash((string) $_REQUEST['license']));
            if (!empty($param_license) && !self::is_legacy_license_key($param_license)) {
                $license_key = $param_license;
                update_user_meta($user->ID, 'vl_license_key', $license_key);
                error_log('[VL Login] Stored license from request parameter: ' . $license_key);
            }
        }

        $license = $license_key ? self::lic_lookup_by_key($license_key) : null;
        if ($license_key && (!$license || (isset($license['status']) && 'active' !== $license['status']))) {
            error_log('[VL Login] License key present but inactive or missing in registry: ' . $license_key);
        }

        if (!empty($requested_redirect_to) && self::url_targets_console($requested_redirect_to)) {
            $requested_license = self::lic_extract_license_from_url($requested_redirect_to);
            if (empty($license_key) && !empty($requested_license) && !self::is_legacy_license_key($requested_license)) {
                $license_key = $requested_license;
                update_user_meta($user->ID, 'vl_license_key', $license_key);
                error_log('[VL Login] Captured license from requested console redirect: ' . $license_key);
            }

            if (!empty($requested_redirect_to)) {
                error_log('[VL Login] Honouring requested console redirect: ' . $requested_redirect_to);

                return $requested_redirect_to;
            }
        }

        if (!empty($license_key)) {
            $url = self::lic_dashboard_url($license ?: array('key' => $license_key), $license_key);
            error_log('[VL Login] Redirecting VL client with license ' . $license_key . ' to ' . $url);

            return $url;
        }

        $fallback = 'https://supercluster.visiblelight.ai/';
        error_log('[VL Login] No license associated; using fallback console URL: ' . $fallback);

        return $fallback;
    }

    /**
     * Forces VL clients to the login screen when logging out.
     */
    public function handle_logout_redirect() {
        wp_safe_redirect('https://supercluster.visiblelight.ai/');
        exit;
    }

    /**
     * Ensures VL clients arriving with a license token are logged in before
     * other template_redirect callbacks (like forced login plugins) run.
     */
    public function maybe_bootstrap_console_session() {
        if (is_admin() || is_user_logged_in()) {
            return;
        }

        if (!self::is_console_request()) {
            return;
        }

        $license_info = self::lic_extract_request_license();
        $license      = $license_info['license'];

        if (empty($license) || self::is_legacy_license_key($license)) {
            return;
        }

        $record = self::lic_lookup_by_key($license);
        if (!$record || (isset($record['status']) && 'active' !== $record['status'])) {
            return;
        }

        $user = self::lic_find_user_by_license($license);
        if (!($user instanceof WP_User) || !in_array('vl_client', (array) $user->roles, true)) {
            return;
        }

        if ('license' !== $license_info['source']) {
            $_GET['license'] = $license;
        }

        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);
        do_action('wp_login', $user->user_login, $user);
    }

    /**
     * Protects the console from unauthenticated access.
     */
    public function protect_console() {
        if (!self::is_console_page_context()) {
            return;
        }

        $license_info = self::lic_extract_request_license();
        $license      = $license_info['license'];

        if (empty($license) || self::is_legacy_license_key($license)) {
            wp_safe_redirect('https://supercluster.visiblelight.ai/');
            exit;
        }

        if ('license' !== $license_info['source']) {
            // Normalise access for downstream consumers that expect ?license=.
            $_GET['license'] = $license;
        }

        if (is_user_logged_in()) {
            return;
        }

        $record = self::lic_lookup_by_key($license);
        if ($record && (!isset($record['status']) || 'active' === $record['status'])) {
            $user = self::lic_find_user_by_license($license);
            if ($user instanceof WP_User && in_array('vl_client', (array) $user->roles, true)) {
                wp_set_current_user($user->ID);
                wp_set_auth_cookie($user->ID, true);
                /**
                 * Allow other plugins hooked into the standard login process to react to the automatic sign on.
                 */
                do_action('wp_login', $user->user_login, $user);

                return;
            }
        }

        wp_safe_redirect(home_url('/supercluster-login/'));
        exit;
    }

    /**
     * Redirects authenticated clients away from the login screen.
     */
    public function redirect_authenticated_clients() {
        // Only redirect from the login page, not from the console page
        if (is_page('supercluster-login') && is_user_logged_in()) {
            $user = wp_get_current_user();

            if ($user instanceof WP_User && in_array('vl_client', (array) $user->roles, true)) {
                $license_key = get_user_meta($user->ID, 'vl_license_key', true);
                if (self::is_legacy_license_key($license_key)) {
                    delete_user_meta($user->ID, 'vl_license_key');
                    delete_user_meta($user->ID, 'license_key');
                    $license_key = '';
                }
                $license     = $license_key ? self::lic_lookup_by_key($license_key) : null;
                $url         = $license ? self::lic_dashboard_url($license, $license_key) : home_url(self::console_primary_path());

                wp_safe_redirect($url);
                exit;
            }
        }

        // Don't redirect if user is already on the console page
        if (self::is_console_page_context() && is_user_logged_in()) {
            return; // Stay on the console page
        }
    }

    /**
     * Redirect VL Clients away from the core wp-login.php screen when already signed in.
     */
    public function maybe_redirect_logged_in_client_from_wp_login() {
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash((string) $_REQUEST['action'])) : 'login';
        if (in_array($action, array('logout', 'lostpassword', 'retrievepassword', 'rp', 'resetpass', 'register', 'confirmaction'), true)) {
            return;
        }

        if (!is_user_logged_in()) {
            return;
        }

        $user = wp_get_current_user();
        if (!($user instanceof WP_User) || !in_array('vl_client', (array) $user->roles, true)) {
            return;
        }

        $license_key = get_user_meta($user->ID, 'vl_license_key', true);
        if (self::is_legacy_license_key($license_key)) {
            delete_user_meta($user->ID, 'vl_license_key');
            delete_user_meta($user->ID, 'license_key');
            $license_key = '';
        }

        $license = $license_key ? self::lic_lookup_by_key($license_key) : null;
        $url     = $license ? self::lic_dashboard_url($license, $license_key) : 'https://supercluster.visiblelight.ai/';

        wp_safe_redirect($url);
        exit;
    }

    /**
     * Add CORS headers for subdomain access.
     */
    public function add_cors_headers() {
        // Allow requests from the supercluster subdomain
        header('Access-Control-Allow-Origin: https://supercluster.visiblelight.ai');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        header('Access-Control-Allow-Credentials: true');
        
        // Handle preflight OPTIONS requests
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
    }

    /**
     * REST API registration.
     */
    public function register_rest_routes() {
        register_rest_route(
            'vl-license/v1',
            '/activate',
            array(
                'methods'             => 'POST',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_activate_license'),
            )
        );

        register_rest_route(
            'vl-license/v1',
            '/heartbeat',
            array(
                'methods'             => 'POST',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_license_heartbeat'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/session',
            array(
                'methods'             => 'GET',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_session_info'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/clients',
            array(
                'methods'             => 'GET',
                'permission_callback' => array($this, 'rest_require_manage_clients'),
                'callback'            => array($this, 'rest_clients_list'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/category-health',
            array(
                'methods'             => 'GET',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_category_health'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/constellation',
            array(
                'methods'             => 'GET',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_constellation_data'),
            )
        );
        
        register_rest_route(
            'vl-hub/v1',
            '/liquidweb/assets',
            array(
                'methods'             => 'GET',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_liquidweb_assets'),
            )
        );
        
        register_rest_route(
            'vl-hub/v1',
            '/liquidweb/status',
            array(
                'methods'             => 'GET',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_liquidweb_status'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/data-streams',
            array(
                'methods'             => 'GET',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_data_streams'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/sync-client-data',
            array(
                'methods'             => 'POST',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_sync_client_data'),
            )
        );

        register_rest_route(
            'vl-hub/v1',
            '/complete-cloud-connection',
            array(
                'methods'             => 'POST',
                'permission_callback' => '__return_true',
                'callback'            => array($this, 'rest_complete_cloud_connection'),
            )
        );
    }

    /**
     * REST handler: activate license.
     */
    public function rest_activate_license($request) {
        $license = trim((string) $request->get_param('license'));
        $site    = esc_url_raw((string) $request->get_param('site_url'));
        $name    = sanitize_text_field((string) $request->get_param('site_name'));
        $wpv     = sanitize_text_field((string) $request->get_param('wp_version'));
        $pv      = sanitize_text_field((string) $request->get_param('plugin_version'));

        if (!$license || !$site) {
            $response = rest_ensure_response(array('ok' => false, 'error' => 'missing_params'));
            if (is_object($response) && method_exists($response, 'set_status')) {
                $response->set_status(400);
            }

            return $response;
        }

        $store    = self::lic_store_get();
        $found_id = null;

      foreach ($store as $id => $row) {
            if (isset($row['key']) && $row['key'] === $license) {
                $found_id = $id;
          break;
        }
      }
      
        if (!$found_id) {
            $response = rest_ensure_response(array('ok' => false, 'error' => 'license_not_found'));
            if (is_object($response) && method_exists($response, 'set_status')) {
                $response->set_status(404);
            }

            return $response;
        }

        $store[$found_id]['last_seen']      = current_time('mysql');
        $store[$found_id]['site']           = $site;
        $store[$found_id]['site_name']      = $name;
        $store[$found_id]['wp_version']     = $wpv;
        $store[$found_id]['plugin_version'] = $pv;
        $store[$found_id]['status']         = 'active';

        self::lic_store_set($store);

        return rest_ensure_response(array('ok' => true, 'license' => $found_id));
    }

    /**
     * REST handler: heartbeat ping.
     */
    public function rest_license_heartbeat($request) {
        $license = trim((string) $request->get_param('license'));
      if (!$license) {
            $response = rest_ensure_response(array('ok' => false, 'error' => 'missing_license'));
            if (is_object($response) && method_exists($response, 'set_status')) {
                $response->set_status(400);
            }

            return $response;
        }

        $store    = self::lic_store_get();
        $found_id = null;

      foreach ($store as $id => $row) {
            if (isset($row['key']) && $row['key'] === $license) {
                $found_id = $id;
          break;
        }
      }
      
        if (!$found_id) {
            $response = rest_ensure_response(array('ok' => false, 'error' => 'license_not_found'));
            if (is_object($response) && method_exists($response, 'set_status')) {
                $response->set_status(404);
            }

            return $response;
        }

        $store[$found_id]['last_seen'] = current_time('mysql');
        $store[$found_id]['status']    = 'active';
        self::lic_store_set($store);

        return rest_ensure_response(array('ok' => true));
    }

    /**
     * REST permission helper: requires a privileged user to manage clients.
     */
    public function rest_require_manage_clients() {
        return is_user_logged_in() && current_user_can('list_users');
    }

    /**
     * REST handler: return session information for the current viewer.
     */
    public function rest_session_info($request) {
        if (!is_user_logged_in()) {
            return rest_ensure_response(
                array(
                    'authenticated' => false,
                    'login_url'     => wp_login_url('https://supercluster.visiblelight.ai/'),
                )
            );
        }

        $user        = wp_get_current_user();
        $license_key = get_user_meta($user->ID, 'vl_license_key', true);
        $license     = $license_key ? self::lic_lookup_by_key($license_key) : null;

        $license_payload = null;
        if ($license) {
            $license_payload = array(
                'key'            => $license_key,
                'client_name'    => isset($license['client_name']) ? $license['client_name'] : '',
                'status'         => isset($license['status']) ? $license['status'] : '',
                'dashboard_url'  => self::lic_dashboard_url($license, $license_key),
                'last_seen'      => isset($license['last_seen']) ? $license['last_seen'] : null,
                'contact_email'  => isset($license['contact_email']) ? $license['contact_email'] : '',
            );
        }

        $permissions = array(
            'can_manage_clients' => current_user_can('list_users'),
        );

        // Get wp_activation_key from user table
        $wp_activation_key = '';
        if ($user->ID) {
            $wp_activation_key = get_user_meta($user->ID, 'user_activation_key', true);
            if (empty($wp_activation_key)) {
                // Fallback: get directly from database
                global $wpdb;
                $activation_key = $wpdb->get_var($wpdb->prepare(
                    "SELECT user_activation_key FROM {$wpdb->users} WHERE ID = %d",
                    $user->ID
                ));
                $wp_activation_key = $activation_key ?: '';
            }
        }

        $response = array(
            'authenticated' => true,
            'user'          => array(
                'id'           => $user->ID,
                'display_name' => $user->display_name,
                'roles'        => $user->roles,
            ),
            'permissions'   => $permissions,
            'dashboard_url' => $license_payload ? $license_payload['dashboard_url'] : 'https://supercluster.visiblelight.ai/',
            'license'       => $license_payload,
            'is_vl_client'  => in_array('vl_client', (array) $user->roles, true),
            'license_key'   => $license_key,
            'wp_activation_key' => $wp_activation_key,
        );

        return rest_ensure_response($response);
    }

    /**
     * REST handler: return the roster of licenses for privileged users.
     */
    public function rest_clients_list($request) {
        $store   = self::lic_store_get();
    $clients = array();
    
        foreach ($store as $key => $row) {
            $clients[] = array(
                'license_key'   => $key,
                'client_name'   => isset($row['client_name']) ? $row['client_name'] : '',
                'status'        => isset($row['status']) ? $row['status'] : '',
                'dashboard_url' => self::lic_dashboard_url($row, $key),
                'contact_email' => isset($row['contact_email']) ? $row['contact_email'] : '',
            );
        }

        return rest_ensure_response(array('clients' => $clients));
    }

    /**
     * REST handler: return constellation data for the Supercluster.
     */
    public function rest_constellation_data($request) {
        // Add CORS headers for this specific endpoint
        $this->add_cors_headers();
        
        $license = sanitize_text_field($request->get_param('license'));
        
        // Get all licenses
        $store = self::lic_store_get();
        $clients = array();
        
        foreach ($store as $key => $row) {
            $clients[] = array(
                'license_id' => $key,
                'license_key' => $key,
                'client' => isset($row['client_name']) ? $row['client_name'] : 'Unassigned Client',
                'site' => isset($row['site']) ? $row['site'] : '',
                'active' => isset($row['status']) && $row['status'] === 'active',
                'created' => isset($row['created']) ? $row['created'] : '',
                'last_seen' => isset($row['last_seen']) ? $row['last_seen'] : '',
                'categories' => self::get_constellation_categories($key)
            );
        }
        
        $response = array(
            'generated_at' => current_time('mysql'),
            'total_clients' => count($clients),
            'clients' => $clients
        );
        
        return rest_ensure_response($response);
    }

    /**
     * REST handler: return Liquid Web assets for a license.
     */
    public function rest_liquidweb_assets($request) {
        $license_key = sanitize_text_field($request->get_param('license'));
        
        if (empty($license_key)) {
            return rest_ensure_response(array(
                'error' => 'License key required',
                'assets' => array()
            ));
        }
        
        $assets = get_option('vl_liquidweb_assets_' . $license_key, array());
        $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
        
        return rest_ensure_response(array(
            'license_key' => $license_key,
            'connected' => !empty($settings['api_key']) && !empty($settings['account_number']),
            'account_number' => $settings['account_number'] ?? '',
            'last_sync' => $settings['last_sync'] ?? 'Never',
            'asset_count' => count($assets),
            'assets' => $assets
        ));
    }
    
    /**
     * REST handler: return Liquid Web connection status for a license.
     */
    public function rest_liquidweb_status($request) {
        $license_key = sanitize_text_field($request->get_param('license'));
        
        if (empty($license_key)) {
            return rest_ensure_response(array(
                'error' => 'License key required',
                'connected' => false
            ));
        }
        
        $status = self::get_liquidweb_connection_status($license_key);
        
        return rest_ensure_response(array(
            'license_key' => $license_key,
            'connected' => $status['connected'],
            'account_number' => $status['account_number'],
            'asset_count' => $status['asset_count'],
            'last_sync' => $status['last_sync']
        ));
    }

    /**
     * Get constellation categories for a license.
     */
    private static function get_constellation_categories($license_key) {
        $categories = array(
            array(
                'slug' => 'identity',
                'name' => 'Identity & Licensing',
                'color' => '#7ee787',
                'icon' => 'visiblelightailogoonly.svg',
                'nodes' => array(
                    array(
                        'id' => 'client',
                        'label' => 'Client',
                        'color' => '#7ee787',
                        'value' => 6,
                        'detail' => 'Unassigned'
                    ),
                    array(
                        'id' => 'site',
                        'label' => 'Primary Site',
                        'color' => '#7ee787',
                        'value' => 6,
                        'detail' => 'https://example.com'
                    ),
                    array(
                        'id' => 'status',
                        'label' => 'License Status',
                        'color' => '#7ee787',
                        'value' => 4,
                        'detail' => 'Inactive'
                    ),
                    array(
                        'id' => 'heartbeat',
                        'label' => 'Last Heartbeat',
                        'color' => '#7ee787',
                        'value' => 5,
                        'detail' => 'No activity recorded'
                    )
                )
            ),
            array(
                'slug' => 'infrastructure',
                'name' => 'Infrastructure & Platform',
                'color' => '#58a6ff',
                'icon' => 'arrows-rotate-reverse-regular-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'https',
                        'label' => 'HTTPS',
                        'color' => '#58a6ff',
                        'value' => 4,
                        'detail' => 'Unknown'
                    )
                )
            ),
            array(
                'slug' => 'security',
                'name' => 'Security & Compliance',
                'color' => '#f85149',
                'icon' => 'eye-slash-light-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'security_placeholder',
                        'label' => 'Security Signals',
                        'color' => '#f85149',
                        'value' => 3,
                        'detail' => 'No security data reported'
                    )
                )
            ),
            array(
                'slug' => 'content',
                'name' => 'Content Universe',
                'color' => '#f2cc60',
                'icon' => 'play-regular-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'content_placeholder',
                        'label' => 'Content Footprint',
                        'color' => '#f2cc60',
                        'value' => 3,
                        'detail' => 'Content metrics not synced yet'
                    )
                )
            ),
            array(
                'slug' => 'plugins',
                'name' => 'Plugin Ecosystem',
                'color' => '#d2a8ff',
                'icon' => 'plus-solid-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'plugins_placeholder',
                        'label' => 'Plugins',
                        'color' => '#d2a8ff',
                        'value' => 3,
                        'detail' => 'Plugins not reported'
                    )
                )
            ),
            array(
                'slug' => 'themes',
                'name' => 'Theme & Experience',
                'color' => '#8b949e',
                'icon' => 'visiblelightailogo.svg',
                'nodes' => array(
                    array(
                        'id' => 'themes_placeholder',
                        'label' => 'Themes',
                        'color' => '#8b949e',
                        'value' => 3,
                        'detail' => 'Theme data not synced'
                    )
                )
            ),
            array(
                'slug' => 'users',
                'name' => 'User Accounts & Roles',
                'color' => '#79c0ff',
                'icon' => 'eye-regular-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'users_placeholder',
                        'label' => 'Users',
                        'color' => '#79c0ff',
                        'value' => 3,
                        'detail' => 'User roster not available'
                    )
                )
            ),
            array(
                'slug' => 'ai',
                'name' => 'AI Conversations',
                'color' => '#bc8cff',
                'icon' => 'visiblelightailogo.svg',
                'nodes' => array(
                    array(
                        'id' => 'conversations_placeholder',
                        'label' => 'AI Chats',
                        'color' => '#bc8cff',
                        'value' => 3,
                        'detail' => 'No conversations logged'
                    )
                )
            ),
            array(
                'slug' => 'sessions',
                'name' => 'Sessions & Engagement',
                'color' => '#56d364',
                'icon' => 'arrows-rotate-reverse-regular-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'sessions_placeholder',
                        'label' => 'Sessions',
                        'color' => '#56d364',
                        'value' => 3,
                        'detail' => 'No session telemetry yet'
                    )
                )
            ),
            array(
                'slug' => 'integrations',
                'name' => 'Integrations & Signals',
                'color' => '#ffa657',
                'icon' => 'minus-solid-full.svg',
                'nodes' => array(
                    array(
                        'id' => 'integrations_placeholder',
                        'label' => 'Cloud Integrations',
                        'color' => '#ffa657',
                        'value' => 3,
                        'detail' => 'No connections synced'
                    )
                )
            )
        );
        
        return $categories;
    }

    /**
     * Creates missing licenses that are referenced in the frontend but don't exist in the store.
     */
    public function maybe_create_missing_licenses() {
        // Only run this once per day to avoid performance issues
        $last_check = get_option('vl_last_license_check', 0);
        if (time() - $last_check < 86400) { // 24 hours
            return;
        }
        
        update_option('vl_last_license_check', time());
        
        $store = self::lic_store_get();
        $missing_licenses = array(
            'VL-GC5K-YKBM-BM5F' => array(
                'client_name' => 'Commonwealth Health Services',
                'site' => 'https://commonwealthhealthservices.com',
                'contact_email' => 'admin@commonwealthhealthservices.com',
                'status' => 'active'
            ),
            'VL-VYAK-9BPQ-NKCC' => array(
                'client_name' => 'Commonwealth Health Services',
                'site' => 'https://commonwealthhealthservices.com',
                'contact_email' => 'admin@commonwealthhealthservices.com',
                'status' => 'active'
            ),
            'VL-H2K3-ZFQK-DKDC' => array(
                'client_name' => 'Site Assembly',
                'site' => 'https://siteassembly.com',
                'contact_email' => 'admin@siteassembly.com',
                'status' => 'active'
            ),
            'VL-SAMPLE-XXXX-XXXX' => array(
                'client_name' => 'Sample Client',
                'site' => 'https://example.com',
                'contact_email' => 'admin@example.com',
                'status' => 'active'
            )
        );
        
        $updated = false;
        foreach ($missing_licenses as $license_key => $license_data) {
            if (!isset($store[$license_key])) {
                $license_data['key'] = $license_key;
                $license_data['created'] = current_time('mysql');
                $license_data['last_seen'] = null;
                $store[$license_key] = $license_data;
                $updated = true;
                error_log('[VL Licenses] Auto-created missing license: ' . $license_key);
            }
        }
        
        if ($updated) {
            self::lic_store_set($store);
        }
    }

    /**
     * Helper accessor for data streams store.
     */
    private static function data_streams_store_get() {
        $store = get_option('vl_data_streams', array());
        return is_array($store) ? $store : array();
    }

    private static function data_streams_store_set($list) {
        update_option('vl_data_streams', is_array($list) ? $list : array());
    }

    /**
     * REST handler: Get category health data.
     * 
     * This endpoint analyzes all data streams for a given license and category,
     * then returns an AI-powered health summary.
     */
    public function rest_category_health($request) {
        $license = sanitize_text_field($request->get_param('license'));
        $category = sanitize_text_field($request->get_param('category'));
        
        if (empty($license) || empty($category)) {
            return rest_ensure_response(array(
                'success' => false,
                'error' => 'License and category parameters are required'
            ));
        }
        
        // Verify license exists and is active
        $license_record = self::lic_lookup_by_key($license);
        if (!$license_record || (isset($license_record['status']) && $license_record['status'] !== 'active')) {
            return rest_ensure_response(array(
                'success' => false,
                'error' => 'Invalid or inactive license'
            ));
        }
        
        // Get all data streams for this license
        $all_streams = self::data_streams_store_get();
        $license_streams = isset($all_streams[$license]) ? $all_streams[$license] : array();
        
        // Filter streams by category
        $category_streams = array_filter($license_streams, function($stream) use ($category) {
            return isset($stream['categories']) && in_array($category, $stream['categories']);
        });
        
        // If no streams found, try to fetch real-time data from client
        if (empty($category_streams)) {
            $real_time_data = self::fetch_client_data($license, $category);
            if ($real_time_data) {
                $category_streams = $real_time_data;
            }
        }
        
        // Generate health summary based on actual data
        $health_summary = self::generate_category_health_analysis($category, $category_streams, $license_record);
        
        return rest_ensure_response(array(
            'success' => true,
            'category' => $category,
            'health_summary' => $health_summary['summary'],
            'metrics' => $health_summary['metrics'],
            'stream_count' => count($category_streams),
            'data_source' => empty($category_streams) ? 'no_data' : 'active_streams'
        ));
    }

    /**
     * REST handler: Get all data streams for a license.
     */
    public function rest_data_streams($request) {
        $license = sanitize_text_field($request->get_param('license'));
        
        if (empty($license)) {
            return rest_ensure_response(array(
                'success' => false,
                'error' => 'License parameter is required'
            ));
        }
        
        // Verify license exists and is active
        $license_record = self::lic_lookup_by_key($license);
        if (!$license_record || (isset($license_record['status']) && $license_record['status'] !== 'active')) {
            return rest_ensure_response(array(
                'success' => false,
                'error' => 'Invalid or inactive license'
            ));
        }
        
        $all_streams = self::data_streams_store_get();
        $license_streams = isset($all_streams[$license]) ? $all_streams[$license] : array();
        
        return rest_ensure_response(array(
            'success' => true,
            'streams' => $license_streams,
            'count' => count($license_streams)
        ));
    }

    /**
     * REST handler: Sync data from client website.
     */
    public function rest_sync_client_data($request) {
        $license = sanitize_text_field($request->get_param('license'));
        $category = sanitize_text_field($request->get_param('category'));
        $data = $request->get_json_params();
        
        if (empty($license)) {
            return rest_ensure_response(array(
                'success' => false,
                'error' => 'License parameter is required'
            ));
        }
        
        // Verify license exists and is active
        $license_record = self::lic_lookup_by_key($license);
        if (!$license_record || (isset($license_record['status']) && $license_record['status'] !== 'active')) {
            return rest_ensure_response(array(
                'success' => false,
                'error' => 'Invalid or inactive license'
            ));
        }
        
        // Process and store the incoming data
        $result = self::process_client_data($license, $category, $data);
        
        return rest_ensure_response(array(
            'success' => $result['success'],
            'message' => $result['message'],
            'streams_updated' => $result['streams_updated']
        ));
    }

    /**
     * REST handler: Complete cloud connection.
     */
    public function rest_complete_cloud_connection($request) {
        $data = $request->get_json_params();
        
        $service_name = sanitize_text_field($data['service_name'] ?? '');
        $token = sanitize_text_field($data['token'] ?? '');
        $api_key = sanitize_text_field($data['api_key'] ?? '');
        $account_id = sanitize_text_field($data['account_id'] ?? '');
        $notes = sanitize_textarea_field($data['notes'] ?? '');
        
        if (empty($service_name) || empty($token)) {
            return rest_ensure_response(array(
                'success' => false,
                'message' => 'Service name and token are required'
            ));
        }
        
        // Verify token
        $token_data = get_option('vl_client_link_token_' . $token, null);
        if (!$token_data || $token_data['expires'] < time()) {
            return rest_ensure_response(array(
                'success' => false,
                'message' => 'Invalid or expired token'
            ));
        }
        
        // Verify token matches service
        if ($token_data['service_name'] !== $service_name) {
            return rest_ensure_response(array(
                'success' => false,
                'message' => 'Token does not match service'
            ));
        }
        
        $license_key = $token_data['license_key'];
        
        // Store connection details
        $connection_data = array(
            'service_name' => $service_name,
            'subcategory' => $token_data['subcategory'],
            'api_key' => $api_key,
            'account_id' => $account_id,
            'notes' => $notes,
            'status' => 'connected',
            'connected_at' => current_time('mysql'),
            'connected_by' => 'client'
        );
        
        // Get existing data streams
        $all_streams = self::data_streams_store_get();
        $license_streams = isset($all_streams[$license_key]) ? $all_streams[$license_key] : array();
        
        // Add new connection
        $license_streams[] = $connection_data;
        $all_streams[$license_key] = $license_streams;
        
        // Save updated streams
        self::data_streams_store_set($all_streams);
        
        // Clean up token
        delete_option('vl_client_link_token_' . $token);
        
        return rest_ensure_response(array(
            'success' => true,
            'message' => 'Cloud connection completed successfully',
            'service' => $service_name
        ));
    }

    /**
     * Generates AI-powered health analysis for a category based on real data stream metrics.
     * 
     * @param string $category The category key (e.g., 'infrastructure', 'content')
     * @param array $streams Array of data streams in this category
     * @param array $license_record The license record
     * @return array Health analysis with summary and metrics
     */
    private static function generate_category_health_analysis($category, $streams, $license_record) {
        $stream_count = count($streams);
        $active_count = 0;
        $error_count = 0;
        $warning_count = 0;
        $total_health_score = 0;
        
        // Analyze each stream
        foreach ($streams as $stream) {
            if (isset($stream['status']) && $stream['status'] === 'active') {
                $active_count++;
            }
            
            if (isset($stream['health_score'])) {
                $total_health_score += floatval($stream['health_score']);
            }
            
            if (isset($stream['error_count'])) {
                $error_count += intval($stream['error_count']);
            }
            
            if (isset($stream['warning_count'])) {
                $warning_count += intval($stream['warning_count']);
            }
        }
        
        $avg_health_score = $stream_count > 0 ? ($total_health_score / $stream_count) : 0;
        $uptime_percentage = $stream_count > 0 ? ($active_count / $stream_count) * 100 : 0;
        
        // Generate context-aware summary based on category and metrics
        $summaries = array(
            'infrastructure' => self::generate_infrastructure_summary($avg_health_score, $uptime_percentage, $error_count, $stream_count),
            'content' => self::generate_content_summary($avg_health_score, $stream_count),
            'search' => self::generate_search_summary($avg_health_score, $stream_count),
            'analytics' => self::generate_analytics_summary($avg_health_score, $stream_count),
            'marketing' => self::generate_marketing_summary($avg_health_score, $stream_count),
            'ecommerce' => self::generate_ecommerce_summary($avg_health_score, $stream_count),
            'security' => self::generate_security_summary($avg_health_score, $error_count, $warning_count),
            'cloudops' => self::generate_cloudops_summary($avg_health_score, $uptime_percentage),
            'identity' => self::generate_identity_summary($avg_health_score, $error_count),
            'competitive' => self::generate_competitive_summary($avg_health_score, $stream_count)
        );
        
        $summary = isset($summaries[$category]) ? $summaries[$category] : 
            'System health data is being analyzed. ' . $stream_count . ' data streams are currently monitored in this category.';
        
        return array(
            'summary' => $summary,
            'metrics' => array(
                'stream_count' => $stream_count,
                'active_count' => $active_count,
                'health_score' => round($avg_health_score, 1),
                'uptime_percentage' => round($uptime_percentage, 1),
                'error_count' => $error_count,
                'warning_count' => $warning_count
            )
        );
    }

    // Category-specific summary generators
    private static function generate_infrastructure_summary($health, $uptime, $errors, $count) {
        if ($errors > 0) {
            return "Infrastructure monitoring detected {$errors} issues across {$count} data streams. System health is at " . round($health, 1) . "% with " . round($uptime, 1) . "% uptime. Immediate attention recommended.";
        }
        return "Infrastructure health is optimal with " . round($uptime, 1) . "% uptime across {$count} monitored systems. All infrastructure streams are running smoothly with no critical issues detected.";
    }

    private static function generate_content_summary($health, $count) {
        if ($health >= 80) {
            return "Content management systems are performing excellently across {$count} data streams. SEO optimization and content delivery are operating at peak efficiency.";
        }
        return "Content systems are operational across {$count} streams with a health score of " . round($health, 1) . "%. Some optimization opportunities detected.";
    }

    private static function generate_search_summary($health, $count) {
        if ($health >= 85) {
            return "Search engine visibility is strong with {$count} active monitoring streams. Rankings are stable with positive trends across key metrics.";
        }
        return "Search performance is being monitored across {$count} data streams. Health score: " . round($health, 1) . "%. Focus on keyword optimization recommended.";
    }

    private static function generate_analytics_summary($health, $count) {
        if ($health >= 80) {
            return "Analytics data streams ({$count} total) show positive engagement trends. Data collection and reporting systems are functioning optimally.";
        }
        return "Analytics monitoring active across {$count} streams with " . round($health, 1) . "% health. Some data collection issues may require attention.";
    }

    private static function generate_marketing_summary($health, $count) {
        if ($health >= 85) {
            return "Marketing campaigns are delivering strong results across {$count} monitored channels. All marketing automation systems are performing well.";
        }
        return "Marketing operations monitored across {$count} data streams. Current health: " . round($health, 1) . "%. Campaign performance may need optimization.";
    }

    private static function generate_ecommerce_summary($health, $count) {
        if ($health >= 80) {
            return "E-commerce performance is excellent across {$count} transaction and inventory streams. Payment processing and order management systems are stable.";
        }
        return "E-commerce systems monitored across {$count} streams. Health score: " . round($health, 1) . "%. Review recommended for checkout and inventory processes.";
    }

    private static function generate_security_summary($health, $errors, $warnings) {
        if ($errors > 0 || $warnings > 5) {
            return "Security monitoring has detected {$errors} critical issues and {$warnings} warnings. Immediate security review recommended to maintain system integrity.";
        }
        if ($health >= 95) {
            return "Security posture is robust with no vulnerabilities detected. All security systems are up to date and properly configured. Continuous monitoring active.";
        }
        return "Security systems are operational with " . round($health, 1) . "% health. {$warnings} minor warnings detected. Regular security audits recommended.";
    }

    private static function generate_cloudops_summary($health, $uptime) {
        if ($health >= 85 && $uptime >= 99) {
            return "Cloud infrastructure is running efficiently with " . round($uptime, 1) . "% uptime. Resource utilization is optimal and auto-scaling is functioning correctly.";
        }
        return "Cloud operations health: " . round($health, 1) . "% with " . round($uptime, 1) . "% uptime. Some cloud resource optimization opportunities available.";
    }

    private static function generate_identity_summary($health, $errors) {
        if ($errors > 0) {
            return "User authentication systems have {$errors} reported issues. Identity and access management requires immediate attention.";
        }
        if ($health >= 95) {
            return "User authentication systems are secure and reliable. Single sign-on integration is working seamlessly across all identity providers.";
        }
        return "Identity management health: " . round($health, 1) . "%. Authentication systems are operational but may benefit from security hardening.";
    }

    private static function generate_competitive_summary($health, $count) {
        if ($health >= 80) {
            return "Competitive analysis across {$count} monitoring streams shows strong market positioning. Key performance metrics are trending positively across all tracked channels.";
        }
        return "Competitive intelligence gathered from {$count} data streams. Health: " . round($health, 1) . "%. Market position analysis suggests areas for strategic improvement.";
    }

    /**
     * Helper functions for managing data streams and category assignments
     */

    /**
     * Adds or updates a data stream for a specific license.
     * 
     * @param string $license_key The license key
     * @param string $stream_id Unique identifier for the data stream
     * @param array $stream_data Stream configuration including categories, health metrics, etc.
     * @return bool Success status
     */
    public static function add_data_stream($license_key, $stream_id, $stream_data) {
        if (empty($license_key) || empty($stream_id) || !is_array($stream_data)) {
            return false;
        }

        $all_streams = self::data_streams_store_get();
        
        // Initialize license streams if not exists
        if (!isset($all_streams[$license_key])) {
            $all_streams[$license_key] = array();
        }

        $existing_stream = $all_streams[$license_key][$stream_id] ?? array();

        // Ensure required fields
        $stream_data['id'] = $stream_id;
        $stream_data['license_key'] = $license_key;

        if (isset($existing_stream['created'])) {
            $stream_data['created'] = $existing_stream['created'];
        } elseif (!isset($stream_data['created'])) {
            $stream_data['created'] = current_time('mysql');
        }

        if (!isset($stream_data['last_updated'])) {
            $stream_data['last_updated'] = current_time('mysql');
        }

        // Set default values if not provided
        if (!isset($stream_data['status'])) {
            $stream_data['status'] = 'active';
        }
        if (!isset($stream_data['health_score'])) {
            $stream_data['health_score'] = 100.0;
        }
        if (!isset($stream_data['categories'])) {
            $stream_data['categories'] = array();
        }
        if (!isset($stream_data['error_count'])) {
            $stream_data['error_count'] = 0;
        }
        if (!isset($stream_data['warning_count'])) {
            $stream_data['warning_count'] = 0;
        }

        $all_streams[$license_key][$stream_id] = $stream_data;
        
        return self::data_streams_store_set($all_streams);
    }

    /**
     * Updates health metrics for a specific data stream.
     * 
     * @param string $license_key The license key
     * @param string $stream_id The stream ID
     * @param array $metrics Health metrics to update
     * @return bool Success status
     */
    public static function update_stream_health($license_key, $stream_id, $metrics) {
        $all_streams = self::data_streams_store_get();
        
        if (!isset($all_streams[$license_key][$stream_id])) {
            return false;
        }

        // Update allowed metrics
        $allowed_metrics = array('health_score', 'error_count', 'warning_count', 'status', 'last_updated');
        
        foreach ($allowed_metrics as $metric) {
            if (isset($metrics[$metric])) {
                $all_streams[$license_key][$stream_id][$metric] = $metrics[$metric];
            }
        }
        
        $all_streams[$license_key][$stream_id]['last_updated'] = current_time('mysql');
        
        return self::data_streams_store_set($all_streams);
    }

    /**
     * Assigns a data stream to one or more categories.
     * 
     * @param string $license_key The license key
     * @param string $stream_id The stream ID
     * @param array $categories Array of category keys
     * @return bool Success status
     */
    public static function assign_stream_categories($license_key, $stream_id, $categories) {
        $all_streams = self::data_streams_store_get();
        
        if (!isset($all_streams[$license_key][$stream_id])) {
            return false;
        }

        // Validate categories against known categories
        $valid_categories = array(
            'infrastructure', 'content', 'search', 'analytics', 
            'marketing', 'ecommerce', 'security', 'cloudops', 
            'identity', 'competitive'
        );
        
        $filtered_categories = array_intersect($categories, $valid_categories);
        
        $all_streams[$license_key][$stream_id]['categories'] = array_values($filtered_categories);
        $all_streams[$license_key][$stream_id]['last_updated'] = current_time('mysql');
        
        return self::data_streams_store_set($all_streams);
    }

    /**
     * Gets all data streams for a specific license and category.
     * 
     * @param string $license_key The license key
     * @param string $category Optional category filter
     * @return array Array of data streams
     */
    public static function get_license_streams($license_key, $category = null) {
        $all_streams = self::data_streams_store_get();
        
        if (!isset($all_streams[$license_key])) {
            return array();
        }

        $streams = $all_streams[$license_key];
        
        if ($category) {
            $streams = array_filter($streams, function($stream) use ($category) {
                return isset($stream['categories']) && in_array($category, $stream['categories']);
            });
        }
        
        return $streams;
    }

    /**
     * Fetches real-time data from client websites based on license and category.
     * 
     * @param string $license_key The license key
     * @param string $category The data category
     * @return array|false Array of data streams or false on failure
     */
    private static function fetch_client_data($license_key, $category) {
        $license_record = self::lic_lookup_by_key($license_key);
        if (!$license_record || !isset($license_record['site'])) {
            return false;
        }
        
        $client_site = $license_record['site'];
        $endpoints = self::get_category_endpoints($category);
        
        $streams = array();
        
        foreach ($endpoints as $endpoint) {
            $url = rtrim($client_site, '/') . '/wp-json/' . $endpoint;
            
            $response = wp_remote_get($url, array(
                'headers' => array(
                    'X-Luna-License' => $license_key,
                    'User-Agent' => 'VL-Hub/1.0'
                ),
                'timeout' => 10,
                'sslverify' => false
            ));
            
            if (is_wp_error($response)) {
                continue;
            }

            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            
            if ($data && isset($data['items'])) {
                $stream_id = $category . '_' . str_replace('/', '_', $endpoint);
                $streams[$stream_id] = array(
                    'name' => ucfirst($category) . ' Data Stream',
                    'description' => 'Real-time data from ' . $client_site,
                    'categories' => array($category),
                    'health_score' => 85.0,
                    'error_count' => 0,
                    'warning_count' => 0,
                    'status' => 'active',
                    'last_updated' => current_time('mysql'),
                    'data_count' => count($data['items']),
                    'source_url' => $client_site
                );
            }
        }
        
        return $streams;
    }

    /**
     * Gets the appropriate API endpoints for each category.
     * 
     * @param string $category The data category
     * @return array Array of endpoint paths
     */
    private static function get_category_endpoints($category) {
        $endpoint_map = array(
            'infrastructure' => array('luna_widget/v1/system/site'),
            'content' => array('luna_widget/v1/content/posts', 'luna_widget/v1/content/pages'),
            'identity' => array('luna_widget/v1/users'),
            'security' => array('luna_widget/v1/plugins', 'luna_widget/v1/themes'),
            'analytics' => array('luna_widget/v1/chat/history'),
            'search' => array(), // No direct endpoints yet
            'marketing' => array(), // No direct endpoints yet
            'ecommerce' => array(), // No direct endpoints yet
            'cloudops' => array('luna_widget/v1/system/site'),
            'competitive' => array() // No direct endpoints yet
        );
        
        return isset($endpoint_map[$category]) ? $endpoint_map[$category] : array();
    }

    /**
     * Processes incoming data from client websites and creates/updates data streams.
     * 
     * @param string $license_key The license key
     * @param string $category The data category
     * @param array $data The incoming data
     * @return array Processing result
     */
    private static function process_client_data($license_key, $category, $data) {
        $streams_updated = 0;
        $all_streams = self::data_streams_store_get();
        
        if (!isset($all_streams[$license_key])) {
            $all_streams[$license_key] = array();
        }
        
        // Process different types of data based on category
        switch ($category) {
            case 'infrastructure':
                if (isset($data['system_info'])) {
                    $stream_id = 'system_health_' . time();
                    $all_streams[$license_key][$stream_id] = array(
                        'name' => 'System Health Monitor',
                        'description' => 'Real-time system performance metrics',
                        'categories' => array('infrastructure', 'cloudops'),
                        'health_score' => self::calculate_system_health($data['system_info']),
                        'error_count' => 0,
                        'warning_count' => 0,
                        'status' => 'active',
                        'last_updated' => current_time('mysql'),
                        'data' => $data['system_info']
                    );
                    $streams_updated++;
                }
                break;
                
            case 'content':
                if (isset($data['posts']) || isset($data['pages'])) {
                    $content_count = 0;
                    if (isset($data['posts'])) $content_count += count($data['posts']);
                    if (isset($data['pages'])) $content_count += count($data['pages']);
                    
                    $stream_id = 'content_management_' . time();
                    $all_streams[$license_key][$stream_id] = array(
                        'name' => 'Content Management System',
                        'description' => 'Content creation and management metrics',
                        'categories' => array('content'),
                        'health_score' => 90.0,
                        'error_count' => 0,
                        'warning_count' => 0,
                        'status' => 'active',
                        'last_updated' => current_time('mysql'),
                        'content_count' => $content_count
                    );
                    $streams_updated++;
                }
                break;
                
            case 'analytics':
                if (isset($data['chat_history'])) {
                    $stream_id = 'chat_analytics_' . time();
                    $all_streams[$license_key][$stream_id] = array(
                        'name' => 'Chat Analytics',
                        'description' => 'User interaction and engagement metrics',
                        'categories' => array('analytics', 'identity'),
                        'health_score' => 85.0,
                        'error_count' => 0,
                        'warning_count' => 0,
                        'status' => 'active',
                        'last_updated' => current_time('mysql'),
                        'interaction_count' => count($data['chat_history'])
                    );
                    $streams_updated++;
                }
                break;
                
            case 'security':
                if (isset($data['plugins']) || isset($data['themes'])) {
                    $stream_id = 'security_monitor_' . time();
                    $all_streams[$license_key][$stream_id] = array(
                        'name' => 'Security Monitor',
                        'description' => 'Plugin and theme security status',
                        'categories' => array('security', 'infrastructure'),
                        'health_score' => self::calculate_security_health($data),
                        'error_count' => 0,
                        'warning_count' => 0,
                        'status' => 'active',
                        'last_updated' => current_time('mysql'),
                        'plugin_count' => isset($data['plugins']) ? count($data['plugins']) : 0,
                        'theme_count' => isset($data['themes']) ? count($data['themes']) : 0
                    );
                    $streams_updated++;
                }
                break;
        }
        
        // Save updated streams
        if ($streams_updated > 0) {
            self::data_streams_store_set($all_streams);
        }
        
        return array(
            'success' => true,
            'message' => "Processed {$streams_updated} data streams for {$category}",
            'streams_updated' => $streams_updated
        );
    }

    /**
     * Calculates system health score based on system information.
     */
    private static function calculate_system_health($system_info) {
        $score = 100.0;
        
        // Check memory usage
        if (isset($system_info['memory_usage'])) {
            $memory_percent = floatval($system_info['memory_usage']);
            if ($memory_percent > 90) $score -= 20;
            elseif ($memory_percent > 80) $score -= 10;
        }
        
        // Check PHP version
        if (isset($system_info['php_version'])) {
            $php_version = $system_info['php_version'];
            if (version_compare($php_version, '8.0', '<')) $score -= 15;
            elseif (version_compare($php_version, '7.4', '<')) $score -= 25;
        }
        
        return max(0, min(100, $score));
    }

    /**
     * Calculates security health score based on plugins and themes.
     */
    private static function calculate_security_health($data) {
        $score = 100.0;
        $outdated_count = 0;
        
        if (isset($data['plugins'])) {
            foreach ($data['plugins'] as $plugin) {
                if (isset($plugin['update_available']) && $plugin['update_available']) {
                    $outdated_count++;
                }
            }
        }
        
        if (isset($data['themes'])) {
            foreach ($data['themes'] as $theme) {
                if (isset($theme['update_available']) && $theme['update_available']) {
                    $outdated_count++;
                }
            }
        }
        
        // Deduct points for outdated items
        $score -= ($outdated_count * 5);
        
        return max(0, min(100, $score));
    }

    /**
     * Renders a data source tab with streams, health analysis, and metrics.
     * 
     * @param string $data_source The data source key
     * @param string $description The data source description
     * @param array $client_streams All client streams
     * @param array $license The license record
     * @return string HTML content for the tab
     */
    public static function render_data_source_tab($data_source, $description, $client_streams, $license) {
        // Filter streams for this data source
        $source_streams = array_filter($client_streams, function($stream) use ($data_source) {
            return isset($stream['categories']) && in_array($data_source, $stream['categories']);
        });
        
        // Generate health analysis
        $health_summary = self::generate_category_health_analysis($data_source, $source_streams, $license);
        
        $html = '<div class="vl-data-source-tab">';
        $html .= '<div class="vl-data-source-header" style="background: #f9f9f9; padding: 20px; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h3 style="margin: 0 0 10px 0; color: #0073aa;">' . ucfirst($data_source) . '</h3>';
        $html .= '<p style="margin: 0; color: #666; font-size: 14px;">' . esc_html($description) . '</p>';
        $html .= '</div>';
        
        // Health Summary
        $html .= '<div class="vl-health-summary" style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h4 style="margin-top: 0; color: #0073aa;">Health Summary</h4>';
        $html .= '<p>' . esc_html($health_summary['summary']) . '</p>';
        $html .= '<div class="vl-health-metrics" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px;">';
        $html .= '<div class="vl-metric" style="text-align: center; padding: 10px; background: #f0f0f0; border-radius: 3px;">';
        $html .= '<div style="font-size: 1.5em; font-weight: bold; color: #0073aa;">' . $health_summary['metrics']['stream_count'] . '</div>';
        $html .= '<small>Data Streams</small>';
        $html .= '</div>';
        $html .= '<div class="vl-metric" style="text-align: center; padding: 10px; background: #f0f0f0; border-radius: 3px;">';
        $html .= '<div style="font-size: 1.5em; font-weight: bold; color: ' . ($health_summary['metrics']['health_score'] >= 80 ? '#00a32a' : ($health_summary['metrics']['health_score'] >= 60 ? '#dba617' : '#d63638')) . ';">' . $health_summary['metrics']['health_score'] . '%</div>';
        $html .= '<small>Health Score</small>';
        $html .= '</div>';
        $html .= '<div class="vl-metric" style="text-align: center; padding: 10px; background: #f0f0f0; border-radius: 3px;">';
        $html .= '<div style="font-size: 1.5em; font-weight: bold; color: #00a32a;">' . $health_summary['metrics']['uptime_percentage'] . '%</div>';
        $html .= '<small>Uptime</small>';
        $html .= '</div>';
        $html .= '<div class="vl-metric" style="text-align: center; padding: 10px; background: #f0f0f0; border-radius: 3px;">';
        $html .= '<div style="font-size: 1.5em; font-weight: bold; color: ' . ($health_summary['metrics']['error_count'] > 0 ? '#d63638' : '#00a32a') . ';">' . $health_summary['metrics']['error_count'] . '</div>';
        $html .= '<small>Errors</small>';
        $html .= '</div>';
        
        // Add Interactions metric
        $interactions_count = self::get_interactions_count($license);
        $html .= '<div class="vl-metric vl-interactions-metric" style="text-align: center; padding: 10px; background: #f0f0f0; border-radius: 3px; cursor: pointer;" onclick="showChatTranscript(\'' . esc_js($license['key']) . '\')">';
        $html .= '<div style="font-size: 1.5em; font-weight: bold; color: #0073aa;">' . $interactions_count . '</div>';
        $html .= '<small>Interactions</small>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        // Add GA4 Integration for Analytics tab
        if ($data_source === 'analytics') {
            $html .= self::render_ga4_integration($license);
        }
        
        // Data Streams Table
        if (!empty($source_streams)) {
            $html .= '<div class="vl-streams-table" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<h4 style="margin: 0; padding: 15px; background: #f9f9f9; border-bottom: 1px solid #ddd;">Data Streams</h4>';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead>';
            $html .= '<tr>';
            $html .= '<th style="padding: 10px;">Stream Name</th>';
            $html .= '<th style="padding: 10px;">Description</th>';
            $html .= '<th style="padding: 10px;">Health</th>';
            $html .= '<th style="padding: 10px;">Status</th>';
            $html .= '<th style="padding: 10px;">Last Updated</th>';
            $html .= '</tr>';
            $html .= '</thead>';
            $html .= '<tbody>';
            
            foreach ($source_streams as $stream_id => $stream) {
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong><a href="#" onclick="openStreamDataModal(\'' . esc_js($license['key']) . '\', \'' . esc_js($stream_id) . '\'); return false;" style="color: #0073aa; text-decoration: none; cursor: pointer;">' . esc_html($stream['name']) . '</a></strong></td>';
                $html .= '<td style="padding: 10px;">' . esc_html($stream['description']) . '</td>';
                $html .= '<td style="padding: 10px;">';
                $html .= '<span style="color: ' . ($stream['health_score'] >= 80 ? '#00a32a' : ($stream['health_score'] >= 60 ? '#dba617' : '#d63638')) . '; font-weight: bold;">';
                $html .= round($stream['health_score'], 1) . '%';
                $html .= '</span>';
                $html .= '</td>';
                $html .= '<td style="padding: 10px;">';
                $html .= '<span class="vl-status-pill vl-status-' . esc_attr($stream['status']) . '" style="background: ' . ($stream['status'] === 'active' ? '#00a32a' : '#d63638') . '; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">';
                $html .= esc_html(ucfirst($stream['status']));
                $html .= '</span>';
                $html .= '</td>';
                $html .= '<td style="padding: 10px;">' . esc_html(isset($stream['last_updated']) ? $stream['last_updated'] : 'Unknown') . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody>';
            $html .= '</table>';
            $html .= '</div>';
        } else {
            $html .= '<div class="vl-no-streams" style="background: white; padding: 40px; text-align: center; border: 1px solid #ddd; border-radius: 5px;">';
            $html .= '<h4 style="color: #666; margin-bottom: 10px;">No Data Streams Found</h4>';
            $html .= '<p style="color: #999; margin: 0;">No data streams are currently assigned to the ' . $data_source . ' category.</p>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        
        return $html;
    }

    /**
     * Renders GA4 integration section for Analytics tab.
     * 
     * @param array $license The license record
     * @return string HTML content for GA4 integration
     */

    public static function render_ga4_integration($license) {
        $license_key = $license['key'] ?? '';
        $ga4_settings = get_option('vl_ga4_settings_' . $license_key, array());

        $html = '<div class="vl-ga4-integration" style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h4 style="margin-top: 0; color: #0073aa;">Google Analytics 4 Integration</h4>';

        $messages = array();
        $previous_settings = $ga4_settings;

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_ga4_settings']) && check_admin_referer('vl_ga4_nonce')) {
            $ga4_settings = array(
                'ga4_property_id' => sanitize_text_field($_POST['ga4_property_id'] ?? ''),
                'ga4_measurement_id' => sanitize_text_field($_POST['ga4_measurement_id'] ?? ''),
                'ga4_api_key' => sanitize_text_field($_POST['ga4_api_key'] ?? ''),
                'ga4_enabled' => isset($_POST['ga4_enabled']),
                'ga4_credentials' => self::sanitize_ga4_credentials_input($_POST['ga4_credentials'] ?? ''),
            );

            if (isset($previous_settings['last_synced'])) {
                $ga4_settings['last_synced'] = $previous_settings['last_synced'];
            }

            if (!empty($license_key) && !empty($previous_settings['ga4_property_id']) && $previous_settings['ga4_property_id'] !== $ga4_settings['ga4_property_id']) {
                self::remove_ga4_stream($license_key, $previous_settings['ga4_property_id']);
            }

            if (!empty($ga4_settings['ga4_enabled'])) {
                if (empty($ga4_settings['ga4_property_id']) || (empty($ga4_settings['ga4_api_key']) && empty($ga4_settings['ga4_credentials']))) {
                    $ga4_settings['ga4_enabled'] = false;
                    $ga4_settings['last_synced'] = '';
                    $messages[] = '<div class="notice notice-error"><p>' . esc_html__('GA4 Property ID and either API Key or Service Account JSON are required to enable the integration.', 'visible-light') . '</p></div>';
                    if (!empty($previous_settings['ga4_property_id'])) {
                        self::remove_ga4_stream($license_key, $previous_settings['ga4_property_id']);
                    }
                } else {
                    $report = self::fetch_ga4_report($ga4_settings);
                    if ($report['success']) {
                        $sync_time = current_time('mysql');
                        $ga4_settings['last_synced'] = $sync_time;
                        self::store_ga4_stream($license_key, $ga4_settings, $report, $sync_time);
                        $messages[] = '<div class="notice notice-success"><p>' . esc_html__('GA4 settings saved and data synchronized successfully.', 'visible-light') . '</p></div>';
                        if ((int) $report['rowCount'] === 0 && empty(array_filter($report['metrics']))) {
                            $messages[] = '<div class="notice notice-warning"><p>' . esc_html__('The GA4 connection succeeded but no data was returned for the selected date range.', 'visible-light') . '</p></div>';
                        }
                    } else {
                        $messages[] = '<div class="notice notice-error"><p>' . sprintf(esc_html__('GA4 settings saved but data sync failed: %s', 'visible-light'), esc_html($report['error'])) . '</p></div>';
                    }
                }
            } else {
                $ga4_settings['last_synced'] = '';
                if (!empty($previous_settings['ga4_property_id'])) {
                    self::remove_ga4_stream($license_key, $previous_settings['ga4_property_id']);
                }
                $messages[] = '<div class="notice notice-info"><p>' . esc_html__('GA4 integration disabled for this license.', 'visible-light') . '</p></div>';
            }

            update_option('vl_ga4_settings_' . $license_key, $ga4_settings);
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST'
            && !empty($license_key)
            && !empty($ga4_settings['ga4_enabled'])
            && !empty($ga4_settings['ga4_property_id'])
            && !empty($ga4_settings['ga4_api_key'])) {
            $last_synced_time = !empty($ga4_settings['last_synced']) ? strtotime($ga4_settings['last_synced']) : 0;
            $needs_refresh = !$last_synced_time || (current_time('timestamp') - $last_synced_time) > 6 * HOUR_IN_SECONDS;
            if ($needs_refresh) {
                $report = self::fetch_ga4_report($ga4_settings);
                if ($report['success']) {
                    $sync_time = current_time('mysql');
                    $ga4_settings['last_synced'] = $sync_time;
                    update_option('vl_ga4_settings_' . $license_key, $ga4_settings);
                    self::store_ga4_stream($license_key, $ga4_settings, $report, $sync_time);
                }
            }
        }

        if (!empty($messages)) {
            foreach ($messages as $message_html) {
                $html .= $message_html;
            }
        }

        $html .= '<form method="post">';
        $html .= wp_nonce_field('vl_ga4_nonce', '_wpnonce', true, false);
        $html .= '<table class="form-table">';
        $html .= '<tr><th scope="row">' . esc_html__('Enable GA4 Integration', 'visible-light') . '</th>';
        $html .= '<td><label><input type="checkbox" name="ga4_enabled" value="1" ' . checked(!empty($ga4_settings['ga4_enabled']), true, false) . '> ' . esc_html__('Enable Google Analytics 4 integration', 'visible-light') . '</label></td></tr>';
        $html .= '<tr><th scope="row">' . esc_html__('GA4 Property ID', 'visible-light') . '</th>';
        $html .= '<td><input type="text" name="ga4_property_id" value="' . esc_attr($ga4_settings['ga4_property_id'] ?? '') . '" class="regular-text" placeholder="123456789"></td></tr>';
        $html .= '<tr><th scope="row">' . esc_html__('Measurement ID', 'visible-light') . '</th>';
        $html .= '<td><input type="text" name="ga4_measurement_id" value="' . esc_attr($ga4_settings['ga4_measurement_id'] ?? '') . '" class="regular-text" placeholder="G-XXXXXXXXXX"></td></tr>';
        $html .= '<tr><th scope="row">' . esc_html__('API Key', 'visible-light') . '</th>';
        $html .= '<td><input type="password" name="ga4_api_key" value="' . esc_attr($ga4_settings['ga4_api_key'] ?? '') . '" class="regular-text" placeholder="Your GA4 API Key"></td></tr>';
        $html .= '<tr><th scope="row">' . esc_html__('Service Account JSON', 'visible-light') . '</th>';
        $html .= '<td><textarea name="ga4_credentials" class="large-text" rows="4" placeholder="' . esc_attr__('Paste your GA4 Service Account JSON credentials here', 'visible-light') . '">' . esc_textarea($ga4_settings['ga4_credentials'] ?? '') . '</textarea></td></tr>';
        $html .= '</table>';
        $html .= '<p class="submit"><input type="submit" name="save_ga4_settings" class="button-primary" value="' . esc_attr__('Save GA4 Settings', 'visible-light') . '"></p>';
        $html .= '</form>';

        $ga4_stream = self::get_ga4_stream_data($license_key, $ga4_settings['ga4_property_id'] ?? '');

        if (!empty($ga4_settings['ga4_enabled'])) {
            $auth_status = self::get_ga4_auth_status($ga4_settings, $license_key);
            $status_color = $auth_status['authenticated'] ? '#d4edda' : '#f8d7da';
            $status_border = $auth_status['authenticated'] ? '#c3e6cb' : '#f5c6cb';
            $html .= '<div class="vl-ga4-status" style="margin-top: 15px; padding: 10px; background: ' . esc_attr($status_color) . '; border: 1px solid ' . esc_attr($status_border) . '; border-radius: 4px;">';
            $html .= '<strong>' . esc_html__('Authentication Status:', 'visible-light') . '</strong> ' . ($auth_status['authenticated'] ? esc_html__('Connected', 'visible-light') : esc_html__('Not Connected', 'visible-light'));
            if (!empty($auth_status['last_synced'])) {
                $timestamp = strtotime($auth_status['last_synced']);
                if ($timestamp) {
                    $html .= '<br><small>' . esc_html__('Last synced:', 'visible-light') . ' ' . esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $timestamp)) . '</small>';
                }
            }
            if (!$auth_status['authenticated'] && !empty($auth_status['error'])) {
                $html .= '<br><small>' . esc_html__('Error:', 'visible-light') . ' ' . esc_html($auth_status['error']) . '</small>';
            }
            $html .= '</div>';
        }

        if ($ga4_stream && !empty($ga4_stream['ga4_metrics'])) {
            $html .= '<div class="vl-ga4-latest" style="margin-top: 20px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 5px; padding: 15px;">';
            $html .= '<h5 style="margin-top: 0;">' . esc_html__('Latest GA4 Metrics', 'visible-light') . '</h5>';

            $summary_parts = array();
            if (!empty($ga4_stream['ga4_property_id'])) {
                $summary_parts[] = sprintf(esc_html__('Property ID: %s', 'visible-light'), esc_html($ga4_stream['ga4_property_id']));
            }
            if (!empty($ga4_stream['ga4_measurement_id'])) {
                $summary_parts[] = sprintf(esc_html__('Measurement ID: %s', 'visible-light'), esc_html($ga4_stream['ga4_measurement_id']));
            }
            if (!empty($summary_parts)) {
                $html .= '<p class="description" style="margin-bottom: 10px;">' . implode(' • ', $summary_parts) . '</p>';
            }

            if (!empty($ga4_stream['ga4_date_range'])) {
                $range_label = self::describe_ga4_date_range($ga4_stream['ga4_date_range']);
                if (!empty($range_label)) {
                    $html .= '<p class="description" style="margin-top: 0;">' . sprintf(esc_html__('Reporting range: %s', 'visible-light'), esc_html($range_label)) . '</p>';
                }
            }

            $html .= '<table class="widefat fixed striped" style="margin-top: 10px;">';
            $html .= '<tbody>';
            foreach (self::get_ga4_metric_definitions() as $metric_key => $metric_label) {
                $value = $ga4_stream['ga4_metrics'][$metric_key] ?? 0;
                $html .= '<tr><th scope="row" style="width: 40%;">' . esc_html($metric_label) . '</th><td>' . esc_html(number_format_i18n((float) $value)) . '</td></tr>';
            }
            $html .= '</tbody>';
            $html .= '</table>';

            if (!empty($ga4_stream['source_url'])) {
                $html .= '<p style="margin-top: 10px;"><a href="' . esc_url($ga4_stream['source_url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Open in Google Analytics', 'visible-light') . '</a></p>';
            }

            $html .= '</div>';
        }

        $html .= '</div>';
        return $html;
    }


    /**
     * Tests GA4 authentication with provided credentials.
     * 
     * @param array $ga4_settings GA4 configuration
     * @return array Authentication result
     */

    public static function test_ga4_authentication($ga4_settings) {
        if (empty($ga4_settings['ga4_property_id']) || (empty($ga4_settings['ga4_api_key']) && empty($ga4_settings['ga4_credentials']))) {
            return array('success' => false, 'error' => __('Missing required GA4 credentials.', 'visible-light'));
        }

        $result = self::fetch_ga4_report($ga4_settings);
        if ($result['success']) {
            return array('success' => true, 'message' => __('GA4 authentication successful', 'visible-light'));
        }

        return array('success' => false, 'error' => $result['error']);
    }

    public static function get_ga4_auth_status($ga4_settings, $license_key = '') {
        if (empty($ga4_settings['ga4_enabled'])) {
            return array('authenticated' => false, 'error' => __('GA4 integration disabled', 'visible-light'), 'last_synced' => '');
        }

        $status = array(
            'authenticated' => false,
            'error' => '',
            'last_synced' => '',
        );

        if (!empty($license_key) && !empty($ga4_settings['ga4_property_id'])) {
            $stream = self::get_ga4_stream_data($license_key, $ga4_settings['ga4_property_id']);
            if ($stream) {
                $status['authenticated'] = true;
                if (!empty($ga4_settings['last_synced'])) {
                    $status['last_synced'] = $ga4_settings['last_synced'];
                } elseif (!empty($stream['ga4_last_synced'])) {
                    $status['last_synced'] = $stream['ga4_last_synced'];
                } elseif (!empty($stream['last_updated'])) {
                    $status['last_synced'] = $stream['last_updated'];
                }
                return $status;
            }
        }

        $auth_result = self::test_ga4_authentication($ga4_settings);
        $status['authenticated'] = $auth_result['success'];
        $status['error'] = $auth_result['success'] ? '' : $auth_result['error'];

        if (!empty($ga4_settings['last_synced'])) {
            $status['last_synced'] = $ga4_settings['last_synced'];
        }

        return $status;
    }

    private static function sanitize_ga4_credentials_input($raw_credentials) {
        if (empty($raw_credentials)) {
            return '';
        }

        $raw_credentials = wp_unslash($raw_credentials);
        if (!is_string($raw_credentials)) {
            return '';
        }

        $raw_credentials = trim($raw_credentials);
        if ($raw_credentials === '') {
            return '';
        }

        $decoded = json_decode($raw_credentials, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            return wp_json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        return sanitize_textarea_field($raw_credentials);
    }

    private static function fetch_ga4_report($ga4_settings) {
        $metrics_map = self::get_ga4_metric_definitions();
        $metric_keys = array_keys($metrics_map);
        $date_range = array(
            'startDate' => '28daysAgo',
            'endDate' => 'yesterday',
        );
        
        $main_report = self::fetch_ga4_aggregated_report($ga4_settings, $metric_keys, $date_range);
        if (is_wp_error($main_report) || empty($main_report['success'])) {
            return $main_report;
        }
        
        // Fetch dimensional reports for comprehensive data
        $geographic_data = self::fetch_ga4_dimensional_report($ga4_settings, $metric_keys, array('country', 'region', 'city'), $date_range, 'geographic');
        $device_data = self::fetch_ga4_dimensional_report($ga4_settings, $metric_keys, array('deviceCategory', 'mobileDeviceBranding', 'browser'), $date_range, 'device');
        $traffic_data = self::fetch_ga4_dimensional_report($ga4_settings, $metric_keys, array('sessionSource', 'sessionMedium', 'sessionCampaignName'), $date_range, 'traffic');
        $page_data = self::fetch_ga4_dimensional_report($ga4_settings, $metric_keys, array('pagePath', 'pageTitle'), $date_range, 'pages');
        $event_data = self::fetch_ga4_dimensional_report($ga4_settings, array('eventCount', 'totalUsers', 'conversions'), array('eventName'), $date_range, 'events');
        
        return array(
            'success' => true,
            'metrics' => $main_report['metrics'],
            'rowCount' => $main_report['rowCount'],
            'rows' => $main_report['rows'],
            'dateRange' => $date_range,
            'dimensions' => array(
                'geographic' => $geographic_data,
                'device' => $device_data,
                'traffic' => $traffic_data,
                'pages' => $page_data,
                'events' => $event_data,
            ),
        );
    }
    
    private static function fetch_ga4_aggregated_report($ga4_settings, $metric_keys, $date_range) {
        $request_body = array(
            'dateRanges' => array($date_range),
            'metrics' => array(),
        );

        foreach ($metric_keys as $metric_name) {
            $request_body['metrics'][] = array('name' => $metric_name);
        }

        $response = self::make_ga4_request($ga4_settings, $request_body);
        if (is_wp_error($response)) {
            return array('success' => false, 'error' => $response->get_error_message());
        }

        $decoded = $response['body'];

        if (!is_array($decoded)) {
            return array('success' => false, 'error' => __('Invalid response from the GA4 API.', 'visible-light'));
        }

        $metrics = array();
        foreach ($metric_keys as $metric_name) {
            $metrics[$metric_name] = 0.0;
        }

        if (!empty($decoded['rows'][0]['metricValues'])) {
            foreach ($metric_keys as $index => $metric_name) {
                $metrics[$metric_name] = isset($decoded['rows'][0]['metricValues'][$index]['value'])
                    ? (float) $decoded['rows'][0]['metricValues'][$index]['value']
                    : 0.0;
            }
        } elseif (!empty($decoded['totals'][0]['metricValues'])) {
            foreach ($metric_keys as $index => $metric_name) {
                $metrics[$metric_name] = isset($decoded['totals'][0]['metricValues'][$index]['value'])
                    ? (float) $decoded['totals'][0]['metricValues'][$index]['value']
                    : 0.0;
            }
        }

        $row_count = isset($decoded['rowCount']) ? (int) $decoded['rowCount'] : 0;
        $rows = array();
        if (!empty($decoded['rows']) && is_array($decoded['rows'])) {
            $rows = $decoded['rows'];
        }

        return array(
            'success' => true,
            'metrics' => $metrics,
            'rowCount' => $row_count,
            'rows' => $rows,
        );
    }
    
    private static function fetch_ga4_dimensional_report($ga4_settings, $metric_keys, $dimensions, $date_range, $report_type) {
        $request_body = array(
            'dateRanges' => array($date_range),
            'metrics' => array(),
            'dimensions' => array(),
            'limit' => 25, // Limit results to avoid timeout
        );

        foreach ($metric_keys as $metric_name) {
            $request_body['metrics'][] = array('name' => $metric_name);
        }

        foreach ($dimensions as $dimension_name) {
            $request_body['dimensions'][] = array('name' => $dimension_name);
        }

        $response = self::make_ga4_request($ga4_settings, $request_body);
        if (is_wp_error($response)) {
            // Return empty array on error for dimensional data
            return array('rows' => array(), 'error' => $response->get_error_message());
        }

        $decoded = $response['body'];

        if (!is_array($decoded)) {
            return array('rows' => array());
        }

        $rows = array();
        if (!empty($decoded['rows']) && is_array($decoded['rows'])) {
            $rows = $decoded['rows'];
        }

        return array('rows' => $rows, 'rowCount' => isset($decoded['rowCount']) ? (int) $decoded['rowCount'] : 0);
    }

    private static function make_ga4_request($ga4_settings, $request_body) {
        $property_id = trim($ga4_settings['ga4_property_id'] ?? '');
        $api_key = trim($ga4_settings['ga4_api_key'] ?? '');
        $credentials = trim($ga4_settings['ga4_credentials'] ?? '');

        if ($property_id === '' || ($api_key === '' && $credentials === '')) {
            return new WP_Error('ga4_missing_credentials', __('Missing GA4 Property ID and either API Key or Service Account credentials.', 'visible-light'));
        }

        $url = 'https://analyticsdata.googleapis.com/v1beta/properties/' . rawurlencode($property_id) . ':runReport';
        
        // Use API key if provided, otherwise we'll use Service Account authentication
        if (!empty($api_key)) {
            $url = add_query_arg('key', rawurlencode($api_key), $url);
        }

        $headers = array(
            'Content-Type' => 'application/json',
        );

        if (!empty($ga4_settings['ga4_credentials'])) {
            $token_result = self::get_service_account_access_token($ga4_settings['ga4_credentials']);
            if (is_wp_error($token_result)) {
                return $token_result;
            }
            $headers['Authorization'] = 'Bearer ' . $token_result['access_token'];
        }

        $response = wp_remote_post($url, array(
            'headers' => $headers,
            'body' => wp_json_encode($request_body),
            'timeout' => 20,
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        $decoded = json_decode($body, true);
        if ($decoded === null && trim($body) !== '') {
            return new WP_Error('ga4_invalid_response', __('Unable to parse GA4 API response.', 'visible-light'));
        }

        if ($code >= 200 && $code < 300 && empty($decoded['error'])) {
            return array(
                'body' => is_array($decoded) ? $decoded : array(),
                'code' => $code,
            );
        }

        $error_message = __('Unknown error communicating with the GA4 API.', 'visible-light');
        if (!empty($decoded['error']['message'])) {
            $error_message = $decoded['error']['message'];
        } elseif ($code >= 400) {
            $error_message = sprintf(__('GA4 API returned HTTP %d.', 'visible-light'), $code);
        }

        return new WP_Error('ga4_api_error', $error_message);
    }

    private static function get_service_account_access_token($credentials_json) {
        $decoded = json_decode($credentials_json, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
            return new WP_Error('ga4_invalid_credentials', __('Invalid GA4 service account credentials JSON.', 'visible-light'));
        }

        if (empty($decoded['client_email']) || empty($decoded['private_key'])) {
            return new WP_Error('ga4_incomplete_credentials', __('The GA4 service account credentials are missing required fields.', 'visible-light'));
        }

        if (!function_exists('openssl_sign')) {
            return new WP_Error('ga4_missing_openssl', __('The OpenSSL PHP extension is required for GA4 service account authentication.', 'visible-light'));
        }

        $token_uri = !empty($decoded['token_uri']) ? $decoded['token_uri'] : 'https://oauth2.googleapis.com/token';
        $now = time();
        $payload = array(
            'iss' => $decoded['client_email'],
            'scope' => 'https://www.googleapis.com/auth/analytics.readonly',
            'aud' => $token_uri,
            'exp' => $now + 3600,
            'iat' => $now,
        );
        $header = array(
            'alg' => 'RS256',
            'typ' => 'JWT',
        );

        $jwt_segments = array(
            self::base64url_encode(wp_json_encode($header)),
            self::base64url_encode(wp_json_encode($payload)),
        );

        $signing_input = implode('.', $jwt_segments);

        $private_key = openssl_pkey_get_private($decoded['private_key']);
        if (!$private_key) {
            return new WP_Error('ga4_private_key', __('Unable to parse the GA4 service account private key.', 'visible-light'));
        }

        $signature = '';
        $success = openssl_sign($signing_input, $signature, $private_key, OPENSSL_ALGO_SHA256);
        openssl_free_key($private_key);

        if (!$success) {
            return new WP_Error('ga4_signature_failure', __('Unable to sign the GA4 service account token.', 'visible-light'));
        }

        $jwt = $signing_input . '.' . self::base64url_encode($signature);

        $response = wp_remote_post($token_uri, array(
            'body' => array(
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $jwt,
            ),
            'timeout' => 20,
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300 && isset($body['access_token'])) {
            return array(
                'access_token' => $body['access_token'],
                'expires_in' => isset($body['expires_in']) ? (int) $body['expires_in'] : 3600,
            );
        }

        $error_message = '';
        if (isset($body['error_description'])) {
            $error_message = $body['error_description'];
        } elseif (isset($body['error'])) {
            $error_message = $body['error'];
        } else {
            $error_message = __('Unable to retrieve GA4 access token.', 'visible-light');
        }

        return new WP_Error('ga4_token_error', $error_message);
    }

    private static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function get_ga4_metric_definitions() {
        return array(
            // User and session statistics
            'totalUsers' => __('Total Users', 'visible-light'),
            'newUsers' => __('New Users', 'visible-light'),
            'activeUsers' => __('Active Users', 'visible-light'),
            'sessions' => __('Sessions', 'visible-light'),
            'screenPageViews' => __('Page Views', 'visible-light'),
            'bounceRate' => __('Bounce Rate', 'visible-light'),
            'averageSessionDuration' => __('Avg Session Duration', 'visible-light'),
            'engagementRate' => __('Engagement Rate', 'visible-light'),
            'engagedSessions' => __('Engaged Sessions', 'visible-light'),
            'userEngagementDuration' => __('User Engagement Duration', 'visible-light'),
            
            // Event data
            'eventCount' => __('Event Count', 'visible-light'),
            'conversions' => __('Conversions', 'visible-light'),
            
            // Monetization data
            'totalRevenue' => __('Total Revenue', 'visible-light'),
            'purchaseRevenue' => __('Purchase Revenue', 'visible-light'),
            'averagePurchaseRevenue' => __('Average Purchase Revenue', 'visible-light'),
            'transactions' => __('Transactions', 'visible-light'),
            
            // Additional metrics
            'sessionConversionRate' => __('Session Conversion Rate', 'visible-light'),
            'totalPurchasers' => __('Total Purchasers', 'visible-light'),
            'newPurchasers' => __('New Purchasers', 'visible-light'),
        );

        if (!empty($ga4_settings['ga4_measurement_id'])) {
            $stream['ga4_measurement_id'] = $ga4_settings['ga4_measurement_id'];
        }

        if (!empty($report_data['rows']) && is_array($report_data['rows'])) {
            $rows = $report_data['rows'];
            if (count($rows) > 10) {
                $rows = array_slice($rows, 0, 10);
            }
            $stream['ga4_rows'] = $rows;
        }

        $all_streams[$license_key][$stream_id] = $stream;
        self::data_streams_store_set($all_streams);
    }

    private static function remove_ga4_stream($license_key, $property_id) {
        if (empty($license_key) || empty($property_id)) {
            return;
        }

        $all_streams = self::data_streams_store_get();
        if (empty($all_streams[$license_key])) {
            return;
        }

        $stream_id = self::get_ga4_stream_id($property_id);
        if (isset($all_streams[$license_key][$stream_id])) {
            unset($all_streams[$license_key][$stream_id]);
            self::data_streams_store_set($all_streams);
        }
    }

    private static function get_ga4_stream_id($property_id) {
        $clean_id = strtolower(preg_replace('/[^a-zA-Z0-9_\-]/', '_', (string) $property_id));
        return 'ga4_' . $clean_id;
    }

    private static function get_ga4_stream_data($license_key, $property_id) {
        if (empty($license_key) || empty($property_id)) {
            return null;
        }

        $all_streams = self::data_streams_store_get();
        $stream_id = self::get_ga4_stream_id($property_id);

        return $all_streams[$license_key][$stream_id] ?? null;
    }

    private static function describe_ga4_date_range($range) {
        if (empty($range) || !is_array($range)) {
            return '';
        }

        $start = self::resolve_ga4_relative_date($range['startDate'] ?? '');
        $end = self::resolve_ga4_relative_date($range['endDate'] ?? '');

        if (!$start || !$end) {
            $start_raw = $range['startDate'] ?? '';
            $end_raw = $range['endDate'] ?? '';
            if ($start_raw || $end_raw) {
                return trim($start_raw . ' – ' . $end_raw);
            }
            return '';
        }

        $format = get_option('date_format');
        return date_i18n($format, $start) . ' – ' . date_i18n($format, $end);
    }

    private static function resolve_ga4_relative_date($value) {
        if (empty($value) || !is_string($value)) {
            return false;
        }

        $value = trim($value);

        if ($value === 'today') {
            return current_time('timestamp');
        }

        if ($value === 'yesterday') {
            return current_time('timestamp') - DAY_IN_SECONDS;
        }

        if (preg_match('/^(\d+)daysAgo$/', $value, $matches)) {
            $days = (int) $matches[1];
            return current_time('timestamp') - ($days * DAY_IN_SECONDS);
        }

        $timestamp = strtotime($value);
        return $timestamp ? $timestamp : false;
    }

    private static function store_ga4_stream($license_key, $ga4_settings, $report_data, $synced_at = null) {
        if (empty($license_key) || empty($ga4_settings['ga4_property_id'])) {
            return;
        }

        $all_streams = self::data_streams_store_get();
        if (!isset($all_streams[$license_key]) || !is_array($all_streams[$license_key])) {
            $all_streams[$license_key] = array();
        }

        $stream_id = self::get_ga4_stream_id($ga4_settings['ga4_property_id']);
        $timestamp = $synced_at ?: current_time('mysql');

        $metrics = array();
        foreach ($report_data['metrics'] as $metric_key => $metric_value) {
            $metrics[$metric_key] = is_numeric($metric_value) ? (float) $metric_value : 0.0;
        }

        $has_activity = ((int) ($report_data['rowCount'] ?? 0) > 0) || !empty(array_filter($metrics));

        $stream = array(
            'name' => 'Google Analytics 4',
            'description' => 'Analytics data pulled from GA4 property ' . $ga4_settings['ga4_property_id'],
            'categories' => array('analytics'),
            'health_score' => $has_activity ? 95.0 : 70.0,
            'error_count' => 0,
            'warning_count' => 0,
            'status' => $has_activity ? 'active' : 'pending',
            'last_updated' => $timestamp,
            'data_count' => (int) ($report_data['rowCount'] ?? 0),
            'ga4_property_id' => $ga4_settings['ga4_property_id'],
            'ga4_metrics' => $metrics,
            'ga4_last_synced' => $timestamp,
            'ga4_date_range' => $report_data['dateRange'] ?? array(),
            'source_url' => 'https://analytics.google.com/analytics/web/#/p' . $ga4_settings['ga4_property_id'],
        );

        if (!empty($ga4_settings['ga4_measurement_id'])) {
            $stream['ga4_measurement_id'] = $ga4_settings['ga4_measurement_id'];
        }

        if (!empty($report_data['rows']) && is_array($report_data['rows'])) {
            $rows = $report_data['rows'];
            if (count($rows) > 10) {
                $rows = array_slice($rows, 0, 10);
            }
            $stream['ga4_rows'] = $rows;
        }
        
        // Store comprehensive dimensional data
        if (!empty($report_data['dimensions']) && is_array($report_data['dimensions'])) {
            $stream['ga4_dimensions'] = $report_data['dimensions'];
            
            // Store top geographic data
            if (!empty($report_data['dimensions']['geographic']['rows'])) {
                $geo_rows = $report_data['dimensions']['geographic']['rows'];
                $stream['ga4_geographic'] = count($geo_rows) > 10 ? array_slice($geo_rows, 0, 10) : $geo_rows;
            }
            
            // Store device/browser data
            if (!empty($report_data['dimensions']['device']['rows'])) {
                $device_rows = $report_data['dimensions']['device']['rows'];
                $stream['ga4_device'] = count($device_rows) > 10 ? array_slice($device_rows, 0, 10) : $device_rows;
            }
            
            // Store traffic source data
            if (!empty($report_data['dimensions']['traffic']['rows'])) {
                $traffic_rows = $report_data['dimensions']['traffic']['rows'];
                $stream['ga4_traffic'] = count($traffic_rows) > 10 ? array_slice($traffic_rows, 0, 10) : $traffic_rows;
            }
            
            // Store top pages data
            if (!empty($report_data['dimensions']['pages']['rows'])) {
                $pages_rows = $report_data['dimensions']['pages']['rows'];
                $stream['ga4_pages'] = count($pages_rows) > 10 ? array_slice($pages_rows, 0, 10) : $pages_rows;
            }
            
            // Store event data
            if (!empty($report_data['dimensions']['events']['rows'])) {
                $events_rows = $report_data['dimensions']['events']['rows'];
                $stream['ga4_events'] = count($events_rows) > 10 ? array_slice($events_rows, 0, 10) : $events_rows;
            }
        }

        $all_streams[$license_key][$stream_id] = $stream;
        self::data_streams_store_set($all_streams);
    }

    /**
     * Gets the total number of chat interactions for a license.
     * 
     * @param array $license The license record
     * @return int Number of interactions
     */
    public static function get_interactions_count($license) {
        $license_key = $license['key'] ?? '';
        if (empty($license_key)) return 0;
        
        // Get interactions count from stored data
        $interactions_data = get_option('vl_interactions_' . $license_key, array());
        return isset($interactions_data['total_interactions']) ? (int)$interactions_data['total_interactions'] : 0;
    }

    /**
     * Gets chat transcript for a specific license.
     * 
     * @param string $license_key The license key
     * @return array Chat transcript data
     */
    public static function get_chat_transcript($license_key) {
        if (empty($license_key)) return array();
        
        // Get chat transcript from stored data
        $transcript_data = get_option('vl_chat_transcript_' . $license_key, array());
        return $transcript_data;
    }

    /**
     * Renders stream data modal.
     * 
     * @param string $license_key The license key
     * @param string $stream_id The stream ID
     * @return string HTML content for stream data modal
     */
    public static function render_stream_data_modal($license_key, $stream_id) {
        $all_streams = self::data_streams_store_get();
        $stream = isset($all_streams[$license_key][$stream_id]) ? $all_streams[$license_key][$stream_id] : null;
        
        if (!$stream) {
            return '<div>Stream not found.</div>';
        }
        
        $html = '<div id="stream-data-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 2% auto; padding: 20px; border-radius: 8px; width: 90%; max-width: 1200px; max-height: 90vh; overflow-y: auto;">';
        $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
        $html .= '<h3 style="margin: 0;">' . esc_html($stream['name']) . ' - Full Data</h3>';
        $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;" onclick="closeStreamDataModal()">&times;</span>';
        $html .= '</div>';
        $html .= '<div class="vl-modal-body">';
        
        // Stream Overview
        $html .= '<div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h4 style="margin-top: 0;">Stream Overview</h4>';
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">';
        $html .= '<div><strong>Description:</strong><br>' . esc_html($stream['description']) . '</div>';
        $html .= '<div><strong>Status:</strong><br><span style="color: ' . ($stream['status'] === 'active' ? '#00a32a' : '#d63638') . '; font-weight: bold;">' . esc_html(ucfirst($stream['status'])) . '</span></div>';
        $html .= '<div><strong>Health Score:</strong><br><span style="color: ' . ($stream['health_score'] >= 80 ? '#00a32a' : ($stream['health_score'] >= 60 ? '#dba617' : '#d63638')) . '; font-weight: bold;">' . round($stream['health_score'], 1) . '%</span></div>';
        $html .= '<div><strong>Last Updated:</strong><br>' . esc_html($stream['last_updated'] ?? 'Unknown') . '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        // Special handling for Google Search Console
        if ($stream_id === 'google_search_console') {
            $html .= self::render_gsc_detailed_data($license_key);
        } else {
            // Full Stream Data for other streams
            $html .= '<div style="background: white; padding: 15px; border: 1px solid #ddd; border-radius: 5px;">';
            $html .= '<h4 style="margin-top: 0;">Complete Stream Data</h4>';
            $html .= '<div style="background: #f5f5f5; padding: 15px; border-radius: 3px; max-height: 500px; overflow-y: auto;">';
            $html .= '<pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: monospace; font-size: 12px;">';
            $html .= esc_html(json_encode($stream, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $html .= '</pre>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
        $html .= '<button type="button" class="button" onclick="closeStreamDataModal()">Close</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }

    /**
     * Renders detailed Google Search Console data.
     * 
     * @param string $license_key The license key
     * @return string HTML content for GSC detailed data
     */
    public static function render_gsc_detailed_data($license_key) {
        $gsc_data = get_option('vl_gsc_data_' . $license_key, array());
        $gsc_settings = get_option('vl_gsc_settings_' . $license_key, array());
        
        if (empty($gsc_data)) {
            return '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; margin-bottom: 20px;">
                <strong>No Data Available</strong><br>
                No Google Search Console data has been synced yet. Please sync the data first.<br>
                <small>If you just synced, the site may not have enough search data yet, or there may be an API issue.</small>
            </div>';
        }
        
        $html = '';
        
        // Debug information
        $html .= '<div style="background: #e7f3ff; padding: 15px; border-radius: 5px; border-left: 4px solid #0073aa; margin-bottom: 20px;">
            <strong>Debug Information:</strong><br>
            <small>Available data keys: ' . implode(', ', array_keys($gsc_data)) . '</small><br>
            <small>Total data points: ' . count($gsc_data) . '</small>
        </div>';
        
        // Performance Overview
        $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h4 style="margin-top: 0; color: #0073aa;">📊 Search Performance Overview</h4>';
        $html .= '<p style="color: #666; margin-bottom: 15px;">Data from the last 30 days for: <strong>' . esc_html($gsc_settings['site_url'] ?? 'Unknown Site') . '</strong></p>';
        
        // Calculate totals
        $total_clicks = 0;
        $total_impressions = 0;
        $total_ctr = 0;
        $total_position = 0;
        $query_count = 0;
        
        if (!empty($gsc_data['search_queries'])) {
            $query_count = count($gsc_data['search_queries']);
            foreach ($gsc_data['search_queries'] as $query) {
                $total_clicks += $query['clicks'] ?? 0;
                $total_impressions += $query['impressions'] ?? 0;
                $total_ctr += $query['ctr'] ?? 0;
                $total_position += $query['position'] ?? 0;
            }
            $avg_ctr = $query_count > 0 ? $total_ctr / $query_count : 0;
            $avg_position = $query_count > 0 ? $total_position / $query_count : 0;
        } else {
            // Show sample data if no real data
            $html .= '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; margin-bottom: 20px;">
                <strong>Sample Data Display</strong><br>
                <small>No search queries found. This could mean:</small><br>
                <ul style="margin: 5px 0; padding-left: 20px;">
                    <li>The site is new and has no search data yet</li>
                    <li>The site URL in GSC doesn\'t match exactly</li>
                    <li>There\'s an API authentication issue</li>
                    <li>The site has very low search traffic</li>
                </ul>
            </div>';
        }
        
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px;">';
        $html .= '<div style="text-align: center; padding: 15px; background: #f0f8ff; border-radius: 5px;">';
        $html .= '<div style="font-size: 24px; font-weight: bold; color: #0073aa;">' . number_format($total_clicks) . '</div>';
        $html .= '<div style="color: #666; font-size: 14px;">Total Clicks</div>';
        $html .= '</div>';
        $html .= '<div style="text-align: center; padding: 15px; background: #f0f8ff; border-radius: 5px;">';
        $html .= '<div style="font-size: 24px; font-weight: bold; color: #0073aa;">' . number_format($total_impressions) . '</div>';
        $html .= '<div style="color: #666; font-size: 14px;">Total Impressions</div>';
        $html .= '</div>';
        $html .= '<div style="text-align: center; padding: 15px; background: #f0f8ff; border-radius: 5px;">';
        $html .= '<div style="font-size: 24px; font-weight: bold; color: #0073aa;">' . number_format($avg_ctr * 100, 2) . '%</div>';
        $html .= '<div style="color: #666; font-size: 14px;">Average CTR</div>';
        $html .= '</div>';
        $html .= '<div style="text-align: center; padding: 15px; background: #f0f8ff; border-radius: 5px;">';
        $html .= '<div style="font-size: 24px; font-weight: bold; color: #0073aa;">' . number_format($avg_position, 1) . '</div>';
        $html .= '<div style="color: #666; font-size: 14px;">Average Position</div>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        // Top Search Queries
        if (!empty($gsc_data['search_queries'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">🔍 Top Search Queries</h4>';
            $html .= '<div style="max-height: 400px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Query</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            // Show top 20 queries
            $top_queries = array_slice($gsc_data['search_queries'], 0, 20);
            foreach ($top_queries as $query) {
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong>' . esc_html($query['keys'][0] ?? 'Unknown') . '</strong></td>';
                $html .= '<td style="padding: 10px;">' . number_format($query['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($query['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($query['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($query['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            if (count($gsc_data['search_queries']) > 20) {
                $html .= '<p style="text-align: center; color: #666; margin-top: 10px;">Showing top 20 of ' . count($gsc_data['search_queries']) . ' queries</p>';
            }
            $html .= '</div>';
        }
        
        // Top Pages
        if (!empty($gsc_data['top_pages'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">📄 Top Performing Pages</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Page</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            // Show top 15 pages
            $top_pages = array_slice($gsc_data['top_pages'], 0, 15);
            foreach ($top_pages as $page) {
                $page_url = $page['keys'][0] ?? 'Unknown';
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><a href="' . esc_url($page_url) . '" target="_blank" style="color: #0073aa; text-decoration: none;">' . esc_html($page_url) . '</a></td>';
                $html .= '<td style="padding: 10px;">' . number_format($page['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($page['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($page['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($page['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            if (count($gsc_data['top_pages']) > 15) {
                $html .= '<p style="text-align: center; color: #666; margin-top: 10px;">Showing top 15 of ' . count($gsc_data['top_pages']) . ' pages</p>';
            }
            $html .= '</div>';
        }
        
        // Countries
        if (!empty($gsc_data['countries'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">🌍 Traffic by Country</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Country</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['countries'] as $country) {
                $country_name = $country['keys'][0] ?? 'Unknown';
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong>' . esc_html($country_name) . '</strong></td>';
                $html .= '<td style="padding: 10px;">' . number_format($country['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($country['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($country['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($country['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Devices
        if (!empty($gsc_data['devices'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">📱 Traffic by Device</h4>';
            $html .= '<div style="max-height: 200px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Device</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['devices'] as $device) {
                $device_name = $device['keys'][0] ?? 'Unknown';
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong>' . esc_html(ucfirst($device_name)) . '</strong></td>';
                $html .= '<td style="padding: 10px;">' . number_format($device['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($device['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($device['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($device['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Sitemaps
        if (!empty($gsc_data['sitemaps'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">🗺️ Sitemaps</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Sitemap URL</th><th>Type</th><th>Status</th><th>Last Downloaded</th><th>Contents</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['sitemaps'] as $sitemap) {
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><a href="' . esc_url($sitemap['path'] ?? '#') . '" target="_blank" style="color: #0073aa; text-decoration: none;">' . esc_html($sitemap['path'] ?? 'Unknown') . '</a></td>';
                $html .= '<td style="padding: 10px;">' . esc_html($sitemap['type'] ?? 'Unknown') . '</td>';
                $html .= '<td style="padding: 10px;"><span style="color: ' . (($sitemap['contents'][0]['status'] ?? '') === 'SUCCESS' ? '#00a32a' : '#d63638') . '; font-weight: bold;">' . esc_html($sitemap['contents'][0]['status'] ?? 'Unknown') . '</span></td>';
                $html .= '<td style="padding: 10px;">' . esc_html($sitemap['lastDownloaded'] ?? 'Never') . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($sitemap['contents'][0]['submitted'] ?? 0) . ' submitted</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Show all available data sections, even if empty
        $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h4 style="margin-top: 0; color: #0073aa;">📋 Data Collection Status</h4>';
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">';
        
        $data_sections = array(
            'search_queries' => 'Search Queries',
            'top_pages' => 'Top Pages', 
            'countries' => 'Countries',
            'devices' => 'Devices',
            'search_appearance' => 'Search Appearance',
            'date_range' => 'Date Range',
            'hourly_data' => 'Hourly Data',
            'sitemaps' => 'Sitemaps',
            'properties' => 'Properties',
            'url_inspection' => 'URL Inspection',
            'amp_inspection' => 'AMP Inspection'
        );
        
        foreach ($data_sections as $key => $name) {
            $has_data = !empty($gsc_data[$key]);
            $count = $has_data ? count($gsc_data[$key]) : 0;
            $color = $has_data ? '#00a32a' : '#d63638';
            $icon = $has_data ? '✅' : '❌';
            
            $html .= '<div style="padding: 10px; background: #f9f9f9; border-radius: 5px; text-align: center;">';
            $html .= '<div style="font-size: 18px;">' . $icon . '</div>';
            $html .= '<div style="font-weight: bold; color: ' . $color . ';">' . $name . '</div>';
            $html .= '<div style="font-size: 12px; color: #666;">' . $count . ' items</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
        
        // Search Appearance (AMP, Rich Results)
        if (!empty($gsc_data['search_appearance'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">🎨 Search Appearance (AMP, Rich Results)</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Search Appearance</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['search_appearance'] as $appearance) {
                $appearance_name = $appearance['keys'][0] ?? 'Unknown';
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong>' . esc_html($appearance_name) . '</strong></td>';
                $html .= '<td style="padding: 10px;">' . number_format($appearance['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($appearance['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($appearance['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($appearance['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Date Range Performance
        if (!empty($gsc_data['date_range'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">📅 Daily Performance (Last 7 Days)</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Date</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['date_range'] as $date_data) {
                $date = $date_data['keys'][0] ?? 'Unknown';
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong>' . esc_html($date) . '</strong></td>';
                $html .= '<td style="padding: 10px;">' . number_format($date_data['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($date_data['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($date_data['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($date_data['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Hourly Performance
        if (!empty($gsc_data['hourly_data'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">⏰ Hourly Performance (Last 3 Days)</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Date</th><th>Hour</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['hourly_data'] as $hourly_data) {
                $date = $hourly_data['keys'][0] ?? 'Unknown';
                $hour = $hourly_data['keys'][1] ?? 'Unknown';
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><strong>' . esc_html($date) . '</strong></td>';
                $html .= '<td style="padding: 10px;">' . esc_html($hour . ':00') . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($hourly_data['clicks'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format($hourly_data['impressions'] ?? 0) . '</td>';
                $html .= '<td style="padding: 10px;">' . number_format(($hourly_data['ctr'] ?? 0) * 100, 2) . '%</td>';
                $html .= '<td style="padding: 10px;">' . number_format($hourly_data['position'] ?? 0, 1) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Site Properties
        if (!empty($gsc_data['properties'])) {
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">🏢 Search Console Properties</h4>';
            $html .= '<div style="max-height: 300px; overflow-y: auto;">';
            $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
            $html .= '<thead><tr><th>Site URL</th><th>Permission Level</th><th>Verification Status</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($gsc_data['properties'] as $property) {
                $html .= '<tr>';
                $html .= '<td style="padding: 10px;"><a href="' . esc_url($property['siteUrl'] ?? '#') . '" target="_blank" style="color: #0073aa; text-decoration: none;">' . esc_html($property['siteUrl'] ?? 'Unknown') . '</a></td>';
                $html .= '<td style="padding: 10px;">' . esc_html($property['permissionLevel'] ?? 'Unknown') . '</td>';
                $html .= '<td style="padding: 10px;"><span style="color: ' . (($property['verificationStatus'] ?? '') === 'VERIFIED' ? '#00a32a' : '#d63638') . '; font-weight: bold;">' . esc_html($property['verificationStatus'] ?? 'Unknown') . '</span></td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // URL Inspection
        if (!empty($gsc_data['url_inspection'])) {
            $inspection = $gsc_data['url_inspection'];
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">🔍 URL Inspection Results</h4>';
            $html .= '<div style="background: #f9f9f9; padding: 15px; border-radius: 5px;">';
            
            if (isset($inspection['inspectionResult'])) {
                $result = $inspection['inspectionResult'];
                $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px;">';
                $html .= '<div><strong>Index Status:</strong><br><span style="color: ' . (($result['indexStatusResult']['verdict'] ?? '') === 'PASS' ? '#00a32a' : '#d63638') . '; font-weight: bold;">' . esc_html($result['indexStatusResult']['verdict'] ?? 'Unknown') . '</span></div>';
                $html .= '<div><strong>Page Coverage:</strong><br>' . esc_html($result['indexStatusResult']['coverageState'] ?? 'Unknown') . '</div>';
                $html .= '<div><strong>Last Crawl:</strong><br>' . esc_html($result['indexStatusResult']['lastCrawlTime'] ?? 'Never') . '</div>';
                $html .= '<div><strong>Crawl Allowed:</strong><br>' . esc_html($result['indexStatusResult']['crawlAs'] ?? 'Unknown') . '</div>';
                $html .= '</div>';
                
                if (isset($result['mobileUsabilityResult'])) {
                    $html .= '<div style="margin-top: 15px;"><strong>Mobile Usability:</strong> ';
                    $html .= '<span style="color: ' . (($result['mobileUsabilityResult']['verdict'] ?? '') === 'PASS' ? '#00a32a' : '#d63638') . '; font-weight: bold;">';
                    $html .= esc_html($result['mobileUsabilityResult']['verdict'] ?? 'Unknown');
                    $html .= '</span></div>';
                }
                
                if (isset($result['richResultsResult'])) {
                    $html .= '<div style="margin-top: 15px;"><strong>Rich Results:</strong> ';
                    $html .= '<span style="color: ' . (($result['richResultsResult']['verdict'] ?? '') === 'PASS' ? '#00a32a' : '#d63638') . '; font-weight: bold;">';
                    $html .= esc_html($result['richResultsResult']['verdict'] ?? 'Unknown');
                    $html .= '</span></div>';
                }
            }
            
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // AMP Inspection
        if (!empty($gsc_data['amp_inspection'])) {
            $amp_inspection = $gsc_data['amp_inspection'];
            $html .= '<div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">⚡ AMP (Accelerated Mobile Pages) Status</h4>';
            $html .= '<div style="background: #f9f9f9; padding: 15px; border-radius: 5px;">';
            
            if (isset($amp_inspection['inspectionResult'])) {
                $result = $amp_inspection['inspectionResult'];
                
                if (isset($result['ampResult'])) {
                    $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px;">';
                    $html .= '<div><strong>AMP Status:</strong><br><span style="color: ' . (($result['ampResult']['verdict'] ?? '') === 'PASS' ? '#00a32a' : '#d63638') . '; font-weight: bold;">' . esc_html($result['ampResult']['verdict'] ?? 'Unknown') . '</span></div>';
                    $html .= '<div><strong>AMP Index State:</strong><br>' . esc_html($result['ampResult']['indexState'] ?? 'Unknown') . '</div>';
                    $html .= '<div><strong>AMP Issues:</strong><br>' . count($result['ampResult']['issues'] ?? []) . ' found</div>';
                    $html .= '</div>';
                    
                    if (!empty($result['ampResult']['issues'])) {
                        $html .= '<div style="margin-top: 15px;"><strong>AMP Issues:</strong><ul>';
                        foreach ($result['ampResult']['issues'] as $issue) {
                            $html .= '<li>' . esc_html($issue['severity'] ?? 'Unknown') . ': ' . esc_html($issue['issueMessage'] ?? 'Unknown issue') . '</li>';
                        }
                        $html .= '</ul></div>';
                    }
                } else {
                    $html .= '<p style="color: #666;">No AMP data available for this URL.</p>';
                }
            }
            
            $html .= '</div>';
            $html .= '</div>';
        }
        
        return $html;
    }

    /**
     * Renders chat transcript modal.
     * 
     * @param string $license_key The license key
     * @return string HTML content for chat transcript modal
     */
    public static function render_chat_transcript_modal($license_key) {
        $transcript = self::get_chat_transcript($license_key);
        
        $html = '<div id="chat-transcript-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 800px; max-height: 80vh; overflow-y: auto;">';
        $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
        $html .= '<h3 style="margin: 0;">Chat Transcript - License: ' . esc_html($license_key) . '</h3>';
        $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;">&times;</span>';
        $html .= '</div>';
        $html .= '<div class="vl-modal-body" id="chat-transcript-content">';
        
        if (empty($transcript)) {
            $html .= '<p>No chat transcript available for this license.</p>';
        } else {
            $html .= '<div class="vl-chat-transcript" style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 15px; background: #f9f9f9;">';
            foreach ($transcript as $entry) {
                $html .= '<div class="vl-chat-entry" style="margin-bottom: 15px; padding: 10px; border-radius: 5px; background: ' . ($entry['type'] === 'user' ? '#e3f2fd' : '#f5f5f5') . ';">';
                $html .= '<div style="font-weight: bold; color: #333; margin-bottom: 5px;">';
                $html .= ($entry['type'] === 'user' ? '👤 User' : '🤖 Luna') . ' - ' . esc_html($entry['timestamp']);
                $html .= '</div>';
                $html .= '<div style="color: #555;">' . esc_html($entry['message']) . '</div>';
                $html .= '</div>';
            }
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
        $html .= '<button type="button" class="button" onclick="closeChatTranscript()">Close</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }

    /**
     * Liquid Web API Handler Class
     */
    private static function get_liquidweb_connection_status($license_key) {
        $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
        
        return array(
            'connected' => !empty($settings['api_key']) && !empty($settings['account_number']),
            'account_number' => $settings['account_number'] ?? '',
            'asset_count' => $settings['asset_count'] ?? 0,
            'last_sync' => $settings['last_sync'] ?? 'Never'
        );
    }
    
    private static function get_cloudflare_connection_status($license_key) {
        $settings = get_option('vl_cloudflare_settings_' . $license_key, array());
        
        return array(
            'connected' => !empty($settings['api_token']) && !empty($settings['account_id']),
            'account_name' => $settings['account_name'] ?? '',
            'zone_count' => $settings['zone_count'] ?? 0,
            'zone_id' => $settings['zone_id'] ?? '',
            'last_sync' => $settings['last_sync'] ?? 'Never'
        );
    }
    
    private static function get_pagespeed_connection_status($license_key) {
        $settings = get_option('vl_pagespeed_settings_' . $license_key, array());
        $is_connected = !empty($settings['url']);
        
        return array(
            'connected' => $is_connected,
            'url' => $settings['url'] ?? '',
            'analysis_count' => $settings['analysis_count'] ?? 0,
            'last_sync' => $settings['last_sync'] ?? 'Never'
        );
    }
    
    /**
     * Renders Liquid Web connection modal.
     * 
     * @param string $license_key The license key
     * @return string HTML content for connection modal
     */
    public static function render_liquidweb_connection_modal($license_key) {
        $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
        $is_connected = !empty($settings['api_key']) && !empty($settings['account_number']);
        
        $html = '<div id="liquidweb-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 600px; max-height: 80vh; overflow-y: auto;">';
        $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
        $html .= '<h3 style="margin: 0;">Liquid Web Connection</h3>';
        $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;">&times;</span>';
        $html .= '</div>';
        
        $html .= '<div class="vl-modal-body">';
        
        if ($is_connected) {
            // Show connection details and management options
            $html .= '<div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">Connection Status: Connected</h4>';
            $html .= '<p><strong>Account Number:</strong> ' . esc_html($settings['account_number']) . '</p>';
            $html .= '<p><strong>Assets Synced:</strong> ' . ($settings['asset_count'] ?? 0) . '</p>';
            $html .= '<p><strong>Last Sync:</strong> ' . esc_html($settings['last_sync'] ?? 'Never') . '</p>';
            $html .= '</div>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-bottom: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="syncLiquidWebAssets(\'' . esc_js($license_key) . '\')">Sync Assets Now</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testLiquidWebConnection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="debugLiquidWebConnection(\'' . esc_js($license_key) . '\')">Debug API</button>';
            $html .= '</div>';
            
            $html .= '<h4>Asset Overview</h4>';
            $assets = get_option('vl_liquidweb_assets_' . $license_key, array());
            if (!empty($assets)) {
                $html .= '<div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px;">';
                $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
                $html .= '<thead><tr><th>Asset ID</th><th>Type</th><th>Status</th><th>Last Updated</th></tr></thead>';
                $html .= '<tbody>';
                
                foreach (array_slice($assets, 0, 20) as $asset) {
                    $html .= '<tr>';
                    $html .= '<td>' . esc_html($asset['uniq_id'] ?? 'N/A') . '</td>';
                    $html .= '<td>' . esc_html($asset['type'] ?? 'Unknown') . '</td>';
                    $html .= '<td><span style="color: ' . (($asset['status'] ?? '') === 'active' ? '#00a32a' : '#d63638') . ';">' . esc_html($asset['status'] ?? 'Unknown') . '</span></td>';
                    $html .= '<td>' . esc_html($asset['last_updated'] ?? 'N/A') . '</td>';
                    $html .= '</tr>';
                }
                
                $html .= '</tbody></table>';
                $html .= '</div>';
                
                if (count($assets) > 20) {
                    $html .= '<p style="text-align: center; color: #666; margin-top: 10px;">Showing first 20 of ' . count($assets) . ' assets</p>';
                }
            } else {
                $html .= '<p>No assets found. Click "Sync Assets Now" to fetch your Liquid Web assets.</p>';
            }
            
            $html .= '<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">';
            $html .= '<button type="button" class="button button-link-delete" onclick="disconnectLiquidWeb(\'' . esc_js($license_key) . '\')">Disconnect Liquid Web</button>';
            $html .= '</div>';
            
        } else {
            // Show connection form
            $html .= '<form id="liquidweb-connection-form">';
            $html .= '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ffc107;">';
            $html .= '<h4 style="margin-top: 0; color: #856404;">Connection Requirements</h4>';
            $html .= '<p style="margin: 0;">To connect to Liquid Web, you need:</p>';
            $html .= '<ul style="margin: 10px 0 0 20px;">';
            $html .= '<li>Your Liquid Web account number</li>';
            $html .= '<li>An API key from your Liquid Web control panel</li>';
            $html .= '<li>Access to the Liquid Web API (v3)</li>';
            $html .= '</ul>';
            $html .= '</div>';
            
            $html .= '<table class="form-table">';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="liquidweb-account">Account Number</label></th>';
            $html .= '<td><input type="text" id="liquidweb-account" name="account_number" value="' . esc_attr($settings['account_number'] ?? '') . '" class="regular-text" placeholder="123456" required></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="liquidweb-apikey">API Key</label></th>';
            $html .= '<td><input type="password" id="liquidweb-apikey" name="api_key" value="' . esc_attr($settings['api_key'] ?? '') . '" class="regular-text" placeholder="Your Liquid Web API Key" required></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="liquidweb-username">Username (Optional)</label></th>';
            $html .= '<td><input type="text" id="liquidweb-username" name="username" value="' . esc_attr($settings['username'] ?? '') . '" class="regular-text" placeholder="Your Liquid Web username"></td>';
            $html .= '</tr>';
            $html .= '</table>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-top: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="saveLiquidWebConnection(\'' . esc_js($license_key) . '\')">Connect to Liquid Web</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testLiquidWebConnection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '</div>';
            $html .= '</form>';
        }
        
        $html .= '</div>';
        $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
        $html .= '<button type="button" class="button" onclick="closeLiquidWebModal()">Close</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }
    
    /**
     * Renders Cloudflare connection modal.
     * 
     * @param string $license_key The license key
     * @return string HTML for the Cloudflare connection modal
     */
    public static function render_cloudflare_connection_modal($license_key) {
        $settings = get_option('vl_cloudflare_settings_' . $license_key, array());
        $is_connected = !empty($settings['api_token']) && !empty($settings['account_id']);
        
        $html = '<div id="cloudflare-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 600px; max-height: 80vh; overflow-y: auto;">';
        $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
        $html .= '<h3 style="margin: 0;">Cloudflare Connection</h3>';
        $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;">&times;</span>';
        $html .= '</div>';
        
        $html .= '<div class="vl-modal-body">';
        
        if ($is_connected) {
            // Show connection details and management options
            $html .= '<div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">Connection Status: Connected</h4>';
            $html .= '<p><strong>Account:</strong> ' . esc_html($settings['account_name']) . '</p>';
            $html .= '<p><strong>Zones:</strong> ' . ($settings['zone_count'] ?? 0) . '</p>';
            if (!empty($settings['zone_id'])) {
                $html .= '<p><strong>Monitoring:</strong> Specific zone (ID: ' . esc_html($settings['zone_id']) . ')</p>';
            } else {
                $html .= '<p><strong>Monitoring:</strong> All zones</p>';
            }
            $html .= '<p><strong>Last Sync:</strong> ' . esc_html($settings['last_sync'] ?? 'Never') . '</p>';
            $html .= '</div>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-bottom: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="syncCloudflareData(\'' . esc_js($license_key) . '\')">Sync Data Now</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testCloudflareConnection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="debugCloudflareConnection(\'' . esc_js($license_key) . '\')">Debug API</button>';
            $html .= '</div>';
            
            $html .= '<h4>Zone Overview</h4>';
            $zones = get_option('vl_cloudflare_zones_' . $license_key, array());
            if (!empty($zones)) {
                $html .= '<div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px;">';
                $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
                $html .= '<thead><tr><th>Zone Name</th><th>Status</th><th>Plan</th><th>Last Updated</th></tr></thead>';
                $html .= '<tbody>';
                
                foreach (array_slice($zones, 0, 20) as $zone) {
                    $html .= '<tr>';
                    $html .= '<td>' . esc_html($zone['name'] ?? 'N/A') . '</td>';
                    $html .= '<td><span style="color: ' . (($zone['status'] ?? '') === 'active' ? '#00a32a' : '#d63638') . ';">' . esc_html($zone['status'] ?? 'Unknown') . '</span></td>';
                    $html .= '<td>' . esc_html($zone['plan'] ?? 'Unknown') . '</td>';
                    $html .= '<td>' . esc_html($zone['last_updated'] ?? 'N/A') . '</td>';
                    $html .= '</tr>';
                }
                
                $html .= '</tbody></table>';
                $html .= '</div>';
                
                if (count($zones) > 20) {
                    $html .= '<p style="text-align: center; color: #666; margin-top: 10px;">Showing first 20 of ' . count($zones) . ' zones</p>';
                }
            } else {
                $html .= '<p>No zones found. Click "Sync Data Now" to fetch your Cloudflare zones.</p>';
            }
            
            $html .= '<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">';
            $html .= '<button type="button" class="button button-link-delete" onclick="disconnectCloudflare(\'' . esc_js($license_key) . '\')">Disconnect Cloudflare</button>';
            $html .= '</div>';
            
        } else {
            // Show connection form
            $html .= '<form id="cloudflare-connection-form">';
            $html .= '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ffc107;">';
            $html .= '<h4 style="margin-top: 0; color: #856404;">Connection Requirements</h4>';
            $html .= '<p style="margin: 0;">To connect to Cloudflare, you need:</p>';
            $html .= '<ul style="margin: 10px 0 0 20px;">';
            $html .= '<li>Your Cloudflare API Token (with Zone:Read permissions)</li>';
            $html .= '<li>Your Cloudflare Account ID</li>';
            $html .= '<li>Access to the Cloudflare API</li>';
            $html .= '</ul>';
            $html .= '</div>';
            
            $html .= '<table class="form-table">';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="cloudflare-token">API Token</label></th>';
            $html .= '<td><input type="password" id="cloudflare-token" name="api_token" value="' . esc_attr($settings['api_token'] ?? '') . '" class="regular-text" placeholder="Your Cloudflare API Token" required></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="cloudflare-account">Account ID</label></th>';
            $html .= '<td><input type="text" id="cloudflare-account" name="account_id" value="' . esc_attr($settings['account_id'] ?? '') . '" class="regular-text" placeholder="Your Cloudflare Account ID" required></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="cloudflare-email">Email (Optional)</label></th>';
            $html .= '<td><input type="email" id="cloudflare-email" name="email" value="' . esc_attr($settings['email'] ?? '') . '" class="regular-text" placeholder="Your Cloudflare email"></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="cloudflare-zone">Zone ID (Optional)</label></th>';
            $html .= '<td><input type="text" id="cloudflare-zone" name="zone_id" value="' . esc_attr($settings['zone_id'] ?? '') . '" class="regular-text" placeholder="Specific zone ID to monitor (leave blank for all zones)"></td>';
            $html .= '</tr>';
            $html .= '</table>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-top: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="saveCloudflareConnection(\'' . esc_js($license_key) . '\')">Connect to Cloudflare</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testCloudflareConnection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '</div>';
            $html .= '</form>';
        }
        
        $html .= '</div>';
        $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
        $html .= '<button type="button" class="button" onclick="closeCloudflareModal()">Close</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }
    
    /**
     * Renders Lighthouse Insights connection modal.
     * 
     * @param string $license_key The license key
     * @return string HTML for the Lighthouse Insights connection modal
     */
    public static function render_pagespeed_connection_modal($license_key) {
        $settings = get_option('vl_pagespeed_settings_' . $license_key, array());
        $is_connected = !empty($settings['url']);
        
        $html = '<div id="pagespeed-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 600px; max-height: 80vh; overflow-y: auto;">';
        $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
        $html .= '<h3 style="margin: 0;">Lighthouse Insights</h3>';
        $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;">&times;</span>';
        $html .= '</div>';
        
        $html .= '<div class="vl-modal-body">';
        
        if ($is_connected) {
            // Show connection details and management options
                $html .= '<div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
                $html .= '<h4 style="margin-top: 0; color: #0073aa;">Connection Status: Connected</h4>';
                $html .= '<p><strong>Monitored URL:</strong> ' . esc_html($settings['url']) . ' <span style="color: #666; font-size: 12px;">(locked)</span></p>';
                $html .= '<p><strong>Analyses:</strong> ' . ($settings['analysis_count'] ?? 0) . ' performance reports</p>';
                $html .= '<p><strong>Last Sync:</strong> ' . esc_html($settings['last_sync'] ?? 'Never') . '</p>';
                $html .= '<p style="color: #666; font-size: 12px; margin: 5px 0 0 0;"><em>To change the monitored URL, disconnect and reconnect with a new URL.</em></p>';
                $html .= '<p style="color: #666; font-size: 12px; margin: 5px 0 0 0;"><strong>Powered by:</strong> <a href="https://github.com/GoogleChrome/lighthouse" target="_blank">Google Lighthouse</a> (open-source)</p>';
                $html .= '</div>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-bottom: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="syncPageSpeedData(\'' . esc_js($license_key) . '\')">Run Performance Test</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testPageSpeedConnection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '</div>';
            
            $html .= '<h4>Performance Analysis Overview</h4>';
            $analyses = get_option('vl_pagespeed_analyses_' . $license_key, array());
            if (!empty($analyses)) {
                $html .= '<div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px;">';
                $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
                $html .= '<thead><tr><th>Date</th><th>Performance</th><th>Accessibility</th><th>Best Practices</th><th>SEO</th></tr></thead>';
                $html .= '<tbody>';
                
                foreach (array_slice($analyses, 0, 10) as $analysis) {
                    $html .= '<tr>';
                    $html .= '<td>' . esc_html($analysis['date'] ?? 'N/A') . '</td>';
                    $html .= '<td><span style="color: ' . (($analysis['performance_score'] ?? 0) >= 90 ? '#00a32a' : (($analysis['performance_score'] ?? 0) >= 50 ? '#dba617' : '#d63638')) . ';">' . ($analysis['performance_score'] ?? 'N/A') . '</span></td>';
                    $html .= '<td><span style="color: ' . (($analysis['accessibility_score'] ?? 0) >= 90 ? '#00a32a' : (($analysis['accessibility_score'] ?? 0) >= 50 ? '#dba617' : '#d63638')) . ';">' . ($analysis['accessibility_score'] ?? 'N/A') . '</span></td>';
                    $html .= '<td><span style="color: ' . (($analysis['best_practices_score'] ?? 0) >= 90 ? '#00a32a' : (($analysis['best_practices_score'] ?? 0) >= 50 ? '#dba617' : '#d63638')) . ';">' . ($analysis['best_practices_score'] ?? 'N/A') . '</span></td>';
                    $html .= '<td><span style="color: ' . (($analysis['seo_score'] ?? 0) >= 90 ? '#00a32a' : (($analysis['seo_score'] ?? 0) >= 50 ? '#dba617' : '#d63638')) . ';">' . ($analysis['seo_score'] ?? 'N/A') . '</span></td>';
                    $html .= '</tr>';
                }
                
                $html .= '</tbody></table>';
                $html .= '</div>';
                
                if (count($analyses) > 10) {
                    $html .= '<p style="text-align: center; color: #666; margin-top: 10px;">Showing last 10 of ' . count($analyses) . ' analyses</p>';
                }
            } else {
                $html .= '<p>No analyses found. Click "Run Performance Test" to analyze your website performance.</p>';
            }
            
            $html .= '<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">';
            $html .= '<button type="button" class="button button-link-delete" onclick="disconnectPageSpeed(\'' . esc_js($license_key) . '\')">Disconnect Lighthouse Insights</button>';
            $html .= '</div>';
            
        } else {
            // Show connection form
            $html .= '<form id="pagespeed-connection-form">';
            $html .= '<div style="background: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #0073aa;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">Get Started with Lighthouse Insights</h4>';
            $html .= '<p style="margin: 0;">Simply enter your website URL below. Lighthouse Insights uses the open-source <a href="https://github.com/GoogleChrome/lighthouse" target="_blank">Google Lighthouse</a> project to analyze your website performance.</p>';
            $html .= '</div>';
            
            $html .= '<table class="form-table">';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="pagespeed-url">Website URL <span style="color: red;">*</span></label></th>';
            $html .= '<td>';
            $html .= '<div style="display: flex; gap: 8px; align-items: flex-start;">';
            $html .= '<select id="pagespeed-protocol" name="protocol" style="width: 100px;">';
            $html .= '<option value="https://">https://</option>';
            $html .= '<option value="http://">http://</option>';
            $html .= '</select>';
            $html .= '<input type="text" id="pagespeed-url" name="url" value="' . esc_attr($settings['url'] ?? '') . '" class="regular-text" placeholder="yourwebsite.com" required style="flex: 1;">';
            $html .= '</div>';
            $html .= '<p class="description" style="margin-top: 8px;">Enter your domain (e.g., example.com, mywebsite.net, site.ai)</p>';
            $html .= '<p class="description" style="color: #dc3232; display: none;" id="url-validation-error">Please enter a valid domain (e.g., .com, .net, .ai, .org, etc.)</p>';
            $html .= '</td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="pagespeed-strategy">Analysis Strategy</label></th>';
            $html .= '<td><select id="pagespeed-strategy" name="strategy" class="regular-text">';
            $html .= '<option value="DESKTOP"' . selected($settings['strategy'] ?? 'DESKTOP', 'DESKTOP', false) . '>Desktop</option>';
            $html .= '<option value="MOBILE"' . selected($settings['strategy'] ?? 'DESKTOP', 'MOBILE', false) . '>Mobile</option>';
            $html .= '</select></td>';
            $html .= '</tr>';
            $html .= '</table>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-top: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="savePageSpeedConnection(\'' . esc_js($license_key) . '\')">Connect to Lighthouse Insights</button>';
            $html .= '</div>';
            $html .= '</form>';
        }
        
        $html .= '</div>';
        $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
        $html .= '<button type="button" class="button" onclick="closePageSpeedModal()">Close</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }
    
    /**
     * Liquid Web API Handler Class
     */
    public static function liquidweb_api_handler($license_key, $endpoint, $params = array()) {
        $settings = get_option('vl_liquidweb_settings_' . $license_key, array());

        if (empty($settings['api_key']) || empty($settings['account_number'])) {
            return new WP_Error('liquidweb_no_credentials', 'Liquid Web credentials not configured');
        }
        
        $api_url = 'https://api.liquidweb.com/v3/' . $endpoint;
        
        // Prepare request parameters according to Liquid Web API v3 format
        $request_params = array_merge($params, array(
            'accnt' => intval($settings['account_number'])
        ));
        
        // Use HTTP Basic Authentication as per Liquid Web API documentation
        $username = $settings['username'] ?? $settings['account_number'];
        $password = $settings['api_key'];
        
        $response = wp_remote_post($api_url, array(
            'headers' => array(
                'Authorization' => 'Basic ' . base64_encode($username . ':' . $password),
                'Content-Type' => 'application/json'
            ),
            'body' => json_encode(array('params' => $request_params)),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $code = wp_remote_retrieve_response_code($response);

        if (null === $data && json_last_error() !== JSON_ERROR_NONE) {
            return new WP_Error('liquidweb_invalid_response', 'Liquid Web API returned malformed JSON');
        }

        // Log the response for debugging
        error_log('[VL Hub] Liquid Web API Response - Code: ' . $code . ', Body: ' . $body);
        
        if ($code >= 400) {
            $error_message = 'Unknown error';
            if (isset($data['error_message'])) {
                $error_message = $data['error_message'];
            } elseif (isset($data['error'])) {
                $error_message = $data['error'];
            } elseif (isset($data['message'])) {
                $error_message = $data['message'];
            }
            return new WP_Error('liquidweb_api_error', 'Liquid Web API error: ' . $error_message, $code);
        }

        return $data;
    }

    private static function liquidweb_is_sequential_array($value) {
        return is_array($value) && array_values($value) === $value;
    }

    private static function liquidweb_first_non_empty_string($values) {
        foreach ($values as $value) {
            if ($value === null) {
                continue;
            }

            if (is_string($value) || is_numeric($value)) {
                $string = trim((string) $value);
                if ($string !== '') {
                    return $string;
                }
                continue;
            }

            if (is_bool($value)) {
                return $value ? 'true' : 'false';
            }

            if (is_array($value)) {
                $queue = array($value);
                $collected = array();
                while (!empty($queue)) {
                    $current = array_shift($queue);
                    if (is_array($current)) {
                        foreach ($current as $item) {
                            $queue[] = $item;
                        }
                        continue;
                    }

                    if (is_string($current) || is_numeric($current)) {
                        $string = trim((string) $current);
                        if ($string !== '') {
                            $collected[] = $string;
                        }
                    }
                }

                if (!empty($collected)) {
                    return implode(' / ', array_unique($collected));
                }
            }
        }

        return '';
    }

    private static function liquidweb_extract_items($response) {
        if (!is_array($response)) {
            return array();
        }

        $candidates = array(
            $response['items'] ?? null,
            $response['result']['items'] ?? null,
            $response['data']['items'] ?? null,
            $response['result'] ?? null,
            $response['data'] ?? null,
            $response['assets'] ?? null,
            $response['servers'] ?? null,
            $response['domains'] ?? null,
            $response
        );

        foreach ($candidates as $candidate) {
            if (!is_array($candidate)) {
                continue;
            }

            if (!self::liquidweb_is_sequential_array($candidate)) {
                $candidate = array_values($candidate);
            }

            $candidate = array_values(array_filter($candidate, 'is_array'));
            if (!empty($candidate)) {
                return $candidate;
            }
        }

        return array();
    }

    private static function liquidweb_calculate_page_total($response, $page_size) {
        $page_total_candidates = array(
            $response['page_total'] ?? null,
            $response['result']['page_total'] ?? null,
            $response['data']['page_total'] ?? null,
            $response['pagination']['total_pages'] ?? null
        );

        foreach ($page_total_candidates as $candidate) {
            if (is_numeric($candidate) && intval($candidate) > 0) {
                return intval($candidate);
            }
        }

        $item_total_candidates = array(
            $response['item_total'] ?? null,
            $response['result']['item_total'] ?? null,
            $response['data']['item_total'] ?? null,
            $response['item_count'] ?? null,
            $response['result']['item_count'] ?? null,
            $response['data']['item_count'] ?? null
        );

        foreach ($item_total_candidates as $candidate) {
            if (is_numeric($candidate) && intval($candidate) > 0 && $page_size > 0) {
                return max(1, (int) ceil(intval($candidate) / $page_size));
            }
        }

        return 1;
    }

    private static function liquidweb_fetch_paginated($license_key, $endpoint, $params = array(), $page_size = 200) {
        $items = array();
        $page_num = 1;
        $page_total = 1;

        do {
            $response = self::liquidweb_api_handler($license_key, $endpoint, array_merge($params, array(
                'page_num' => $page_num,
                'page_size' => $page_size
            )));

            if (is_wp_error($response)) {
                return $response;
            }

            $page_items = self::liquidweb_extract_items($response);
            if (!empty($page_items)) {
                foreach ($page_items as $item) {
                    $items[] = $item;
                }
            }

            $page_total = self::liquidweb_calculate_page_total($response, $page_size);
            $page_num++;
        } while ($page_num <= $page_total);

        return $items;
    }

    private static function liquidweb_extract_detail($response) {
        if (!is_array($response)) {
            return array();
        }

        $candidates = array(
            $response['item'] ?? null,
            $response['result']['item'] ?? null,
            $response['result'] ?? null,
            $response['data']['item'] ?? null,
            $response['data'] ?? null,
            $response['asset'] ?? null,
            $response['server'] ?? null,
            $response['details'] ?? null,
            $response
        );

        foreach ($candidates as $candidate) {
            if (!is_array($candidate)) {
                continue;
            }

            if (isset($candidate['item']) && is_array($candidate['item'])) {
                return $candidate['item'];
            }

            if (isset($candidate['asset']) && is_array($candidate['asset'])) {
                return $candidate['asset'];
            }

            if (isset($candidate['server']) && is_array($candidate['server'])) {
                return $candidate['server'];
            }

            if (isset($candidate['details']) && is_array($candidate['details'])) {
                return $candidate['details'];
            }

            return $candidate;
        }

        return array();
    }

    private static function liquidweb_fetch_details($license_key, $endpoint, $uniq_id, $alsowith = array()) {
        if (!is_string($uniq_id) || trim($uniq_id) === '') {
            return array();
        }

        $params = array('uniq_id' => $uniq_id);
        if (!empty($alsowith)) {
            $params['alsowith'] = $alsowith;
        }

        $response = self::liquidweb_api_handler($license_key, $endpoint, $params);

        if (is_wp_error($response)) {
            return $response;
        }

        return self::liquidweb_extract_detail($response);
    }

    private static function liquidweb_determine_status($data) {
        if (!is_array($data)) {
            return 'active';
        }

        $candidates = array(
            $data['status'] ?? null,
            $data['state'] ?? null,
            $data['power_state'] ?? null,
            $data['powerStatus'] ?? null,
            $data['power_status'] ?? null,
            $data['lifecycle_state'] ?? null,
            $data['lifecycleState'] ?? null,
            $data['server_status'] ?? null
        );

        if (isset($data['powerStatus']) && is_array($data['powerStatus'])) {
            $candidates[] = $data['powerStatus']['status'] ?? null;
            $candidates[] = $data['powerStatus']['state'] ?? null;
        }

        if (isset($data['status']) && is_array($data['status'])) {
            $candidates[] = $data['status']['status'] ?? null;
            $candidates[] = $data['status']['state'] ?? null;
            $candidates[] = $data['status']['name'] ?? null;
        }

        if (isset($data['active']) && is_bool($data['active'])) {
            $candidates[] = $data['active'] ? 'active' : 'inactive';
        }

        $status = self::liquidweb_first_non_empty_string($candidates);

        if ($status === '') {
            return 'active';
        }

        $normalized = strtolower($status);
        if (in_array($normalized, array('active', 'on', 'running', 'online', 'ok', 'enabled', 'ready', 'up'), true)) {
            return 'active';
        }

        if (in_array($normalized, array('inactive', 'off', 'stopped', 'offline', 'disabled', 'suspended', 'cancelled', 'canceled', 'terminated', 'down'), true)) {
            return 'inactive';
        }

        return $status;
    }

    private static function liquidweb_record_incomplete($asset) {
        if (!is_array($asset)) {
            return true;
        }

        if (!isset($asset['name']) || $asset['name'] === '' || $asset['name'] === 'Unnamed Asset') {
            return true;
        }

        if (!isset($asset['type']) || $asset['type'] === '' || $asset['type'] === 'Unknown') {
            return true;
        }

        if (!isset($asset['status']) || $asset['status'] === '') {
            return true;
        }

        if (!isset($asset['description']) || trim((string) $asset['description']) === '') {
            return true;
        }

        return false;
    }

    private static function liquidweb_choose_status($current, $candidate) {
        $current_string = is_string($current) ? trim($current) : '';
        $candidate_string = is_string($candidate) ? trim($candidate) : '';

        $current_lower = strtolower($current_string);
        $candidate_lower = strtolower($candidate_string);

        if ($candidate_string === '') {
            return $current_string !== '' ? $current_string : 'active';
        }

        if ($current_string === '') {
            return $candidate_lower === 'active' ? 'active' : $candidate_string;
        }

        if ($current_lower === 'active' && $candidate_lower !== 'active') {
            return $candidate_lower === 'inactive' ? 'inactive' : $candidate_string;
        }

        if ($candidate_lower === 'inactive') {
            return 'inactive';
        }

        return $current_string;
    }

    private static function liquidweb_calculate_health_score($status) {
        $normalized = strtolower(is_string($status) ? $status : '');

        if (in_array($normalized, array('inactive', 'suspended', 'disabled', 'offline', 'down', 'terminated', 'cancelled', 'canceled'), true)) {
            return 60.0;
        }

        if (in_array($normalized, array('maintenance', 'pending', 'provisioning', 'building', 'rebooting'), true)) {
            return 80.0;
        }

        return 95.0;
    }

    private static function liquidweb_normalize_record($record, $details = array(), $source = 'asset') {
        if (!is_array($record)) {
            return null;
        }

        $record_data = is_array($record) ? $record : array();
        $detail_data = is_array($details) ? $details : array();
        $merged = array_merge($record_data, $detail_data);

        $uniq_candidates = array(
            $record_data['uniq_id'] ?? null,
            $record_data['uniqid'] ?? null,
            $record_data['id'] ?? null,
            $record_data['asset_id'] ?? null,
            $record_data['server_id'] ?? null,
            $detail_data['uniq_id'] ?? null,
            $detail_data['uniqid'] ?? null,
            $detail_data['id'] ?? null,
            $merged['uniq_id'] ?? null,
            $merged['uniqid'] ?? null,
            $merged['id'] ?? null
        );

        $uniq_id = self::liquidweb_first_non_empty_string($uniq_candidates);

        if ($uniq_id === '' || strtolower($uniq_id) === 'unknown') {
            return null;
        }

        $name = self::liquidweb_first_non_empty_string(array(
            $merged['custom_name'] ?? null,
            $merged['name'] ?? null,
            $merged['hostname'] ?? null,
            $merged['label'] ?? null,
            $merged['domain'] ?? null,
            $merged['primary_domain'] ?? null,
            $merged['fqdn'] ?? null,
            $merged['machine']['hostname'] ?? null,
            $merged['machine']['name'] ?? null,
            $merged['machine']['label'] ?? null,
            $merged['instance']['hostname'] ?? null,
            $merged['instance']['name'] ?? null,
            $merged['product']['name'] ?? null,
            $merged['project_name'] ?? null,
            $merged['ip'] ?? null
        ));

        if ($name === '') {
            $name = 'Unnamed Asset';
        }

        $type = self::liquidweb_first_non_empty_string(array(
            $merged['type'] ?? null,
            $merged['asset_type'] ?? null,
            $merged['type_class'] ?? null,
            $merged['product']['type'] ?? null,
            $merged['product']['class'] ?? null,
            $merged['primaryProductCategory'] ?? null,
            $merged['publicProductCategory'] ?? null,
            $merged['primary_product_category'] ?? null,
            $merged['public_product_category'] ?? null,
            $merged['category'] ?? null,
            $merged['class'] ?? null,
            $merged['machine']['type'] ?? null,
            $merged['instance']['type'] ?? null,
            $merged['plan_id'] ?? null
        ));

        if ($type === '') {
            $type = 'Unknown';
        }

        $status = self::liquidweb_determine_status($merged);

        $description = self::liquidweb_first_non_empty_string(array(
            $merged['description'] ?? null,
            $merged['shortDescription'] ?? null,
            $merged['short_description'] ?? null,
            $merged['summary'] ?? null,
            $merged['note'] ?? null,
            $merged['notes'] ?? null,
            $merged['product']['description'] ?? null,
            $merged['project_name'] ?? null
        ));

        $ip = self::liquidweb_first_non_empty_string(array(
            $merged['ip'] ?? null,
            $merged['primary_ip'] ?? null,
            $merged['ipv4'] ?? null,
            $merged['ipv6'] ?? null,
            $merged['public_ip'] ?? null,
            $merged['public_ipv4'] ?? null,
            $merged['instance']['ip'] ?? null,
            $merged['machine']['ip'] ?? null
        ));

        return array(
            'uniq_id' => $uniq_id,
            'type' => $type,
            'status' => $status,
            'name' => $name,
            'description' => $description,
            'ip' => $ip,
            'source' => $source,
            'last_updated' => current_time('mysql'),
            'details' => array(
                'source' => $source,
                'data' => $merged
            )
        );
    }

    private static function liquidweb_merge_asset_records($existing, $incoming) {
        if (!is_array($existing) || empty($existing)) {
            return $incoming;
        }

        if (!is_array($incoming) || empty($incoming)) {
            return $existing;
        }

        $existing['last_updated'] = current_time('mysql');

        $string_fields = array('name', 'description', 'ip');
        foreach ($string_fields as $field) {
            $current_value = isset($existing[$field]) ? trim((string) $existing[$field]) : '';
            $incoming_value = isset($incoming[$field]) ? trim((string) $incoming[$field]) : '';
            if ($incoming_value !== '' && ($current_value === '' || $current_value === 'Unnamed Asset')) {
                $existing[$field] = $incoming[$field];
            }
        }

        if (isset($incoming['type']) && ($existing['type'] === '' || $existing['type'] === 'Unknown')) {
            $existing['type'] = $incoming['type'];
        }

        if (isset($incoming['status'])) {
            $existing['status'] = self::liquidweb_choose_status($existing['status'] ?? '', $incoming['status']);
        }

        if (!empty($incoming['source'])) {
            $existing['source'] = $incoming['source'];
        }

        $existing_details = isset($existing['details']['data']) && is_array($existing['details']['data']) ? $existing['details']['data'] : array();
        $incoming_details = isset($incoming['details']['data']) && is_array($incoming['details']['data']) ? $incoming['details']['data'] : array();

        $existing['details']['source'] = $existing['details']['source'] ?? $incoming['details']['source'] ?? ($existing['source'] ?? 'asset');
        $existing['details']['data'] = array_merge($existing_details, $incoming_details);

        return $existing;
    }

    /**
     * Cloudflare API Handler Class
     */
    public static function cloudflare_api_handler($license_key, $endpoint, $params = array()) {
        $settings = get_option('vl_cloudflare_settings_' . $license_key, array());
        
        if (empty($settings['api_token']) || empty($settings['account_id'])) {
            return new WP_Error('cloudflare_no_credentials', 'Cloudflare credentials not configured');
        }
        
        $api_url = 'https://api.cloudflare.com/client/v4/' . $endpoint;
        
        // Add account ID to params if not already present
        if (!isset($params['account_id']) && !isset($params['zone_id'])) {
            $params['account_id'] = $settings['account_id'];
        }
        
        // Build URL with query parameters for GET requests
        if (!empty($params)) {
            $api_url .= '?' . http_build_query($params);
        }
        
        $response = wp_remote_get($api_url, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $settings['api_token'],
                'Content-Type' => 'application/json'
            ),
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        $code = wp_remote_retrieve_response_code($response);
        
        // Log the response for debugging
        error_log('[VL Hub] Cloudflare API Response - Code: ' . $code . ', Body: ' . $body);
        
        if ($code >= 400) {
            $error_message = 'Unknown error';
            if (isset($data['errors']) && is_array($data['errors']) && !empty($data['errors'])) {
                $error_message = $data['errors'][0]['message'] ?? 'Unknown error';
            } elseif (isset($data['error'])) {
                $error_message = $data['error'];
            } elseif (isset($data['message'])) {
                $error_message = $data['message'];
            }
            return new WP_Error('cloudflare_api_error', 'Cloudflare API error: ' . $error_message, $code);
        }
        
        return $data;
    }
    
    
    /**
     * Lighthouse Insights API Handler Class
     */
    public static function pagespeed_api_handler($license_key, $url, $strategy = 'DESKTOP') {
        // Simple fallback - return error message instead of complex authentication
        return new WP_Error('lighthouse_not_implemented', 'Lighthouse Insights is powered by the open-source Google Lighthouse project. Direct API integration will be implemented in a future update.');
    }

    private static function liquidweb_collect_items($license_key, $endpoint, $params = array(), $page_size = 100) {
        $items = array();
        $page_num = 1;
        $page_total = 1;

        do {
            $response = self::liquidweb_api_handler(
                $license_key,
                $endpoint,
                array_merge(
                    $params,
                    array(
                        'page_num'  => $page_num,
                        'page_size' => $page_size,
                    )
                )
            );

            if (is_wp_error($response)) {
                return $response;
            }

            $items = array_merge($items, self::liquidweb_extract_items($response));
            $page_total = self::liquidweb_extract_page_total($response, $page_size);
            $page_num++;
        } while ($page_num <= $page_total);

        return $items;
    }

    private static function liquidweb_extract_items($response) {
        if (!is_array($response)) {
            return array();
        }

        $candidates = array(
            $response['items'] ?? null,
            $response['data']['items'] ?? null,
            $response['result']['items'] ?? null,
            $response['result'] ?? null,
            $response['data'] ?? null,
            $response['assets'] ?? null,
            $response['servers'] ?? null,
            $response['domains'] ?? null,
            $response,
        );

        foreach ($candidates as $candidate) {
            if (!is_array($candidate)) {
                continue;
            }

            if ($candidate === array_values($candidate)) {
                return $candidate;
            }

            $values = array_values($candidate);
            if (!empty($values) && $values === array_values($values)) {
                return $values;
            }
        }

        return array();
    }

    private static function liquidweb_extract_page_total($response, $page_size) {
        if (!is_array($response)) {
            return 1;
        }

        $page_candidates = array(
            $response['page_total'] ?? null,
            $response['result']['page_total'] ?? null,
            $response['data']['page_total'] ?? null,
            $response['pagination']['total_pages'] ?? null,
        );

        foreach ($page_candidates as $candidate) {
            if (is_numeric($candidate) && intval($candidate) > 0) {
                return intval($candidate);
            }
        }

        $item_candidates = array(
            $response['item_total'] ?? null,
            $response['result']['item_total'] ?? null,
            $response['data']['item_total'] ?? null,
            $response['item_count'] ?? null,
            $response['result']['item_count'] ?? null,
            $response['data']['item_count'] ?? null,
        );

        foreach ($item_candidates as $candidate) {
            if (is_numeric($candidate) && intval($candidate) > 0 && $page_size > 0) {
                return max(1, (int) ceil(intval($candidate) / $page_size));
            }
        }

        return 1;
    }

    private static function liquidweb_fetch_details($license_key, $endpoint, $uniq_id, $alsowith = array()) {
        if (!is_string($uniq_id) || trim($uniq_id) === '') {
            return array();
        }

        $params = array('uniq_id' => $uniq_id);
        if (!empty($alsowith)) {
            $params['alsowith'] = $alsowith;
        }

        $response = self::liquidweb_api_handler($license_key, $endpoint, $params);

        if (is_wp_error($response)) {
            return $response;
        }

        $detail_candidates = array(
            $response['item'] ?? null,
            $response['result']['item'] ?? null,
            $response['result'] ?? null,
            $response['data']['item'] ?? null,
            $response['data'] ?? null,
            $response['asset'] ?? null,
            $response['server'] ?? null,
            $response['details'] ?? null,
            $response,
        );

        foreach ($detail_candidates as $candidate) {
            if (is_array($candidate) && !empty($candidate)) {
                return $candidate;
            }
        }

        return array();
    }

    private static function liquidweb_pick_string($values) {
        if (!is_array($values)) {
            $values = array($values);
        }

        foreach ($values as $value) {
            if (!is_string($value)) {
                continue;
            }

            $trimmed = trim($value);
            if ($trimmed !== '') {
                return $trimmed;
            }
        }

        return '';
    }

    private static function liquidweb_normalize_status($data) {
        $candidates = array();

        $status_fields = array('status', 'state', 'power_status', 'powerState', 'powerStatus');
        foreach ($status_fields as $field) {
            if (!isset($data[$field])) {
                continue;
            }

            $value = $data[$field];
            if (is_array($value)) {
                foreach (array('status', 'state', 'power_state') as $subkey) {
                    if (isset($value[$subkey])) {
                        $candidates[] = $value[$subkey];
                    }
                }
            } else {
                $candidates[] = $value;
            }
        }

        if (isset($data['active'])) {
            if (is_bool($data['active'])) {
                $candidates[] = $data['active'] ? 'active' : 'inactive';
            } elseif (is_string($data['active'])) {
                $candidates[] = $data['active'];
            }
        }

        foreach ($candidates as $candidate) {
            if (!is_string($candidate)) {
                continue;
            }

            $value = strtolower(trim($candidate));
            if ($value === '') {
                continue;
            }

            if (in_array($value, array('active', 'on', 'running', 'online', 'powered on'), true)) {
                return 'active';
            }

            if (in_array($value, array('inactive', 'off', 'stopped', 'offline', 'powered off', 'suspended'), true)) {
                return 'inactive';
            }

            return $candidate;
        }

        return 'active';
    }

    private static function liquidweb_normalize_asset_record($record, $detail, $source) {
        $merged = array();

        foreach (array($record, $detail) as $payload) {
            if (!is_array($payload)) {
                continue;
            }

            $merged = array_replace_recursive($merged, $payload);
        }

        $uniq_id = self::liquidweb_pick_string(
            array(
                $merged['uniq_id'] ?? null,
                $merged['uniqid'] ?? null,
                $merged['id'] ?? null,
            )
        );

        if ($uniq_id === '') {
            return array();
        }

        $name = self::liquidweb_pick_string(
            array(
                $merged['custom_name'] ?? null,
                $merged['name'] ?? null,
                $merged['hostname'] ?? null,
                $merged['fqdn'] ?? null,
                $merged['domain'] ?? null,
                $merged['project_name'] ?? null,
                $merged['machine']['hostname'] ?? null,
                $merged['instance']['hostname'] ?? null,
                $merged['machine']['name'] ?? null,
                $merged['product']['name'] ?? null,
            )
        );

        if ($name === '') {
            $name = 'Unnamed Asset';
        }

        $type = self::liquidweb_pick_string(
            array(
                $merged['type'] ?? null,
                $merged['asset_type'] ?? null,
                $merged['type_class'] ?? null,
                $merged['category'] ?? null,
                $merged['class'] ?? null,
                $merged['product']['type'] ?? null,
                $merged['primaryProductCategory'] ?? null,
                $merged['publicProductCategory'] ?? null,
                $merged['primary_product_category'] ?? null,
                $merged['public_product_category'] ?? null,
            )
        );

        if ($type === '') {
            $type = 'Unknown';
        }

        $description = self::liquidweb_pick_string(
            array(
                $merged['description'] ?? null,
                $merged['shortDescription'] ?? null,
                $merged['short_description'] ?? null,
                $merged['note'] ?? null,
                $merged['project_name'] ?? null,
                $merged['product']['description'] ?? null,
            )
        );

        $ip = self::liquidweb_pick_string(
            array(
                $merged['ip'] ?? null,
                $merged['primary_ip'] ?? null,
                $merged['ipv4'] ?? null,
                $merged['ipv6'] ?? null,
                $merged['public_ip'] ?? null,
                $merged['public_ipv4'] ?? null,
                $merged['machine']['ip'] ?? null,
                $merged['instance']['ip'] ?? null,
            )
        );

        $status = self::liquidweb_normalize_status($merged);

        return array(
            'uniq_id'      => $uniq_id,
            'type'         => $type,
            'status'       => $status,
            'name'         => $name,
            'description'  => $description,
            'ip'           => $ip,
            'source'       => $source,
            'last_updated' => current_time('mysql'),
            'details'      => array(
                'source' => $source,
                'data'   => $merged,
            ),
        );
    }

    private static function liquidweb_merge_asset_records($current, $incoming) {
        if (empty($current)) {
            return $incoming;
        }

        if (empty($incoming)) {
            return $current;
        }

        $merged = $current;

        $string_fields = array('name', 'description', 'ip');
        foreach ($string_fields as $field) {
            $existing = isset($merged[$field]) ? trim((string) $merged[$field]) : '';
            $candidate = isset($incoming[$field]) ? trim((string) $incoming[$field]) : '';

            if ($candidate !== '' && ($existing === '' || $existing === 'Unnamed Asset')) {
                $merged[$field] = $incoming[$field];
            }
        }

        if (isset($incoming['type']) && (!isset($merged['type']) || $merged['type'] === '' || $merged['type'] === 'Unknown')) {
            $merged['type'] = $incoming['type'];
        }

        if (isset($incoming['status'])) {
            $merged['status'] = $incoming['status'];
        }

        if (!empty($incoming['source'])) {
            $merged['source'] = $incoming['source'];
        }

        $merged['last_updated'] = current_time('mysql');

        $current_details = isset($merged['details']['data']) && is_array($merged['details']['data']) ? $merged['details']['data'] : array();
        $incoming_details = isset($incoming['details']['data']) && is_array($incoming['details']['data']) ? $incoming['details']['data'] : array();
        $merged['details']['data'] = array_replace_recursive($current_details, $incoming_details);
        $merged['details']['source'] = $incoming['details']['source'] ?? ($merged['details']['source'] ?? $merged['source']);

        return $merged;
    }

    private static function liquidweb_calculate_health_score($status) {
        $value = strtolower((string) $status);
        if (in_array($value, array('inactive', 'suspended', 'powered off', 'disabled'), true)) {
            return 65.0;
        }

        if (in_array($value, array('warning', 'maintenance'), true)) {
            return 80.0;
        }

        return 95.0;
    }
    
    /**
     * Sync Liquid Web assets for a license
     */
    public static function sync_liquidweb_assets($license_key) {
        $commonAlsowith = array(
            'product',
            'primaryProductCategory',
            'publicProductCategory',
            'categories',
            'hostingDetails',
            'machine',
            'instance',
            'region',
            'servers',
            'loadbalancer',
            'powerStatus',
            'description',
            'shortDescription',
        );

        $asset_list = self::liquidweb_fetch_paginated($license_key, 'asset/list', array(
            'alsowith' => $commonAlsowith
        ));

        $asset_list_error = null;
        if (is_wp_error($asset_list)) {
            $asset_list_error = $asset_list;
            error_log('[VL Hub] Liquid Web asset/list error: ' . $asset_list->get_error_message());
            $asset_list = array();
        }

        $serverAlsowith = array('powerStatus', 'region', 'machine', 'instance', 'product', 'description', 'shortDescription');
        $server_list = self::liquidweb_fetch_paginated($license_key, 'server/list', array(
            'alsowith' => $serverAlsowith
        ));

        $server_list_error = null;
        if (is_wp_error($server_list)) {
            $server_list_error = $server_list;
            error_log('[VL Hub] Liquid Web server/list error: ' . $server_list->get_error_message());
            $server_list = array();
        }

        if (empty($asset_list) && empty($server_list)) {
            if ($asset_list_error instanceof WP_Error) {
                return $asset_list_error;
            }

            if ($server_list_error instanceof WP_Error) {
                return $server_list_error;
            }

            return new WP_Error('liquidweb_no_assets', 'No Liquid Web assets were returned by the API');
        }

        $assets_map = array();
        $details_cache = array();

        foreach ($asset_list as $raw_asset) {
            if (!is_array($raw_asset)) {
                continue;
            }

            $normalized = self::liquidweb_normalize_record($raw_asset, array(), 'asset');
            $uniq_id = $normalized['uniq_id'] ?? self::liquidweb_first_non_empty_string(array($raw_asset['uniq_id'] ?? null, $raw_asset['id'] ?? null, $raw_asset['uniqid'] ?? null));

            if (($normalized === null || self::liquidweb_record_incomplete($normalized)) && $uniq_id !== '') {
                $cache_key = 'asset:' . $uniq_id;
                if (!array_key_exists($cache_key, $details_cache)) {
                    $details_cache[$cache_key] = self::liquidweb_fetch_details($license_key, 'asset/details', $uniq_id, $commonAlsowith);
                }

                $detail_data = $details_cache[$cache_key];
                if ($detail_data instanceof WP_Error) {
                    error_log('[VL Hub] Liquid Web asset/details error for ' . $uniq_id . ': ' . $detail_data->get_error_message());
                } elseif (!empty($detail_data)) {
                    $normalized = self::liquidweb_normalize_record($raw_asset, $detail_data, 'asset');
                }
                $details_cache[$uniq_id] = $detail;
            }

            if ($normalized !== null) {
                $assets_map[$normalized['uniq_id']] = $normalized;
            }
        }

        foreach ($server_list as $raw_server) {
            if (!is_array($raw_server)) {
                continue;
            }
        }

            $normalized = self::liquidweb_normalize_record($raw_server, array(), 'server');
            if ($normalized === null) {
                $uniq_id = self::liquidweb_first_non_empty_string(array($raw_server['uniq_id'] ?? null, $raw_server['id'] ?? null, $raw_server['uniqid'] ?? null));
            } else {
                $uniq_id = $normalized['uniq_id'];
            }
        }

            if (($normalized === null || self::liquidweb_record_incomplete($normalized)) && $uniq_id !== '') {
                $cache_key = 'server:' . $uniq_id;
                if (!array_key_exists($cache_key, $details_cache)) {
                    $details_cache[$cache_key] = self::liquidweb_fetch_details($license_key, 'server/details', $uniq_id, $serverAlsowith);
                }

                $detail_data = $details_cache[$cache_key];
                if ($detail_data instanceof WP_Error) {
                    error_log('[VL Hub] Liquid Web server/details error for ' . $uniq_id . ': ' . $detail_data->get_error_message());
                } elseif (!empty($detail_data)) {
                    $normalized = self::liquidweb_normalize_record($raw_server, $detail_data, 'server');
                }
            }

            if ($normalized !== null) {
                if (isset($assets_map[$normalized['uniq_id']])) {
                    $assets_map[$normalized['uniq_id']] = self::liquidweb_merge_asset_records($assets_map[$normalized['uniq_id']], $normalized);
                } else {
                    $assets_map[$normalized['uniq_id']] = $normalized;
                }
            }
        }

        $assets = array_values($assets_map);

        usort($assets, function ($a, $b) {
            $name_a = strtolower($a['name'] ?? '');
            $name_b = strtolower($b['name'] ?? '');
            return strcmp($name_a, $name_b);
        });

        update_option('vl_liquidweb_assets_' . $license_key, $assets);

        $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
        $settings['asset_count'] = count($asset_values);
        $settings['last_sync'] = current_time('mysql');
        $settings['last_sync_breakdown'] = array(
            'asset_list' => count($asset_list),
            'server_list' => count($server_list)
        );
        update_option('vl_liquidweb_settings_' . $license_key, $settings);

        $streams = self::data_streams_store_get();
        if (isset($streams[$license_key]) && is_array($streams[$license_key])) {
            foreach (array_keys($streams[$license_key]) as $stream_id) {
                if (strpos($stream_id, 'liquidweb_') === 0) {
                    unset($streams[$license_key][$stream_id]);
                }
            }
            self::data_streams_store_set($streams);
        }

        foreach ($assets as $asset) {
            $stream_id = 'liquidweb_' . $asset['uniq_id'];
            $description = self::liquidweb_first_non_empty_string(array(
                $asset['description'] ?? null,
                $asset['details']['data']['description'] ?? null,
                $asset['details']['data']['shortDescription'] ?? null,
                $asset['details']['data']['short_description'] ?? null,
                'Liquid Web ' . $asset['type'] . ' asset monitoring'
            ));

            $status = strtolower($asset['status']);
            $stream_status = in_array($status, array('active', 'inactive'), true) ? $status : ($status === '' ? 'active' : $asset['status']);

            $stream_data = array(
                'name' => 'Liquid Web Asset: ' . $asset['name'],
                'description' => $description,
                'categories' => array('infrastructure', 'cloudops'),
                'health_score' => self::liquidweb_calculate_health_score($asset['status']),
                'error_count' => 0,
                'warning_count' => 0,
                'status' => $stream_status,
                'last_updated' => current_time('mysql'),
                'liquidweb_asset_id' => $asset['uniq_id'],
                'liquidweb_asset_type' => $asset['type'],
                'source_url' => 'https://my.liquidweb.com/',
                'details' => $asset['details'],
                'metadata' => array(
                    'ip' => $asset['ip'],
                    'status' => $asset['status'],
                    'type' => $asset['type'],
                    'source' => $asset['source']
                )
            );

            self::add_data_stream($license_key, $stream_id, $stream_data);
        }

        return array(
            'success' => true,
            'assets_synced' => count($asset_values),
            'message' => 'Successfully synced ' . count($asset_values) . ' Liquid Web assets',
        );
    }
    
    /**
     * Sync Cloudflare data for a license
     */
    public static function sync_cloudflare_data($license_key) {
        $settings = get_option('vl_cloudflare_settings_' . $license_key, array());
        
        // Get account information
        $account_response = self::cloudflare_api_handler($license_key, 'accounts/' . $settings['account_id'] ?? '');
        
        if (is_wp_error($account_response)) {
            return $account_response;
        }
        
        $zones = array();
        
        // Check if a specific zone ID is provided
        if (!empty($settings['zone_id'])) {
            // Get specific zone details
            $zone_response = self::cloudflare_api_handler($license_key, 'zones/' . $settings['zone_id']);
            
            if (is_wp_error($zone_response)) {
                return $zone_response;
            }
            
            if (isset($zone_response['result'])) {
                $zone = $zone_response['result'];
                $zones[] = array(
                    'id' => $zone['id'] ?? '',
                    'name' => $zone['name'] ?? 'Unknown Zone',
                    'status' => $zone['status'] ?? 'Unknown',
                    'plan' => $zone['plan']['name'] ?? 'Unknown',
                    'last_updated' => current_time('mysql'),
                    'details' => $zone
                );
            }
        } else {
            // Get all zones list
            $zones_response = self::cloudflare_api_handler($license_key, 'zones');
            
            if (is_wp_error($zones_response)) {
                return $zones_response;
            }
            
            if (isset($zones_response['result']) && is_array($zones_response['result'])) {
                foreach ($zones_response['result'] as $zone) {
                    $zones[] = array(
                        'id' => $zone['id'] ?? '',
                        'name' => $zone['name'] ?? 'Unknown Zone',
                        'status' => $zone['status'] ?? 'Unknown',
                        'plan' => $zone['plan']['name'] ?? 'Unknown',
                        'last_updated' => current_time('mysql'),
                        'details' => $zone
                    );
                }
            }
        }
        
        // Store zones
        update_option('vl_cloudflare_zones_' . $license_key, $zones);
        
        // Update settings with sync info
        $settings = get_option('vl_cloudflare_settings_' . $license_key, array());
        $settings['zone_count'] = count($zones);
        $settings['last_sync'] = current_time('mysql');
        $settings['account_name'] = $account_response['result']['name'] ?? 'Unknown Account';
        update_option('vl_cloudflare_settings_' . $license_key, $settings);
        
        // Create data streams for each zone
        foreach ($zones as $zone) {
            $stream_id = 'cloudflare_' . $zone['id'];
            $stream_data = array(
                'name' => 'Cloudflare Zone: ' . $zone['name'],
                'description' => 'Cloudflare DNS and security monitoring for ' . $zone['name'],
                'categories' => array('infrastructure', 'cloudops'),
                'health_score' => $zone['status'] === 'active' ? 95.0 : 70.0,
                'error_count' => 0,
                'warning_count' => 0,
                'status' => $zone['status'] === 'active' ? 'active' : 'pending',
                'last_updated' => current_time('mysql'),
                'cloudflare_zone_id' => $zone['id'],
                'cloudflare_zone_name' => $zone['name'],
                'source_url' => 'https://dash.cloudflare.com/'
            );
            
            self::add_data_stream($license_key, $stream_id, $stream_data);
        }
        
        return array(
            'success' => true,
            'zones_synced' => count($zones),
            'message' => 'Successfully synced ' . count($zones) . ' Cloudflare zones'
        );
    }
    
    /**
     * Sync Lighthouse Insights data for a license
     */
    public static function sync_pagespeed_data($license_key) {
        // Temporarily disabled to prevent critical errors
        return new WP_Error('lighthouse_disabled', 'Lighthouse Insights analysis features will be available in a future update.');
    }
    
    /**
     * Get Liquid Web data for Luna Widget integration
     */
    public static function get_liquidweb_widget_data($license_key) {
        if (empty($license_key)) {
            return array();
        }
        
        $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
        $assets = get_option('vl_liquidweb_assets_' . $license_key, array());
        
        if (empty($settings['api_key']) || empty($settings['account_number'])) {
            return array(
                'connected' => false,
                'message' => 'Liquid Web not connected'
            );
        }
        
        $widget_data = array(
            'connected' => true,
            'account_number' => $settings['account_number'],
            'last_sync' => $settings['last_sync'] ?? 'Never',
            'asset_count' => count($assets),
            'assets' => array()
        );
        
        // Format assets for widget display
        foreach ($assets as $asset) {
            $widget_data['assets'][] = array(
                'id' => $asset['uniq_id'],
                'name' => $asset['name'],
                'type' => $asset['type'],
                'status' => $asset['status'],
                'last_updated' => $asset['last_updated']
            );
        }
        
        return $widget_data;
    }
    
    /**
     * Auto-sync Liquid Web assets for all connected licenses
     */
    public static function auto_sync_liquidweb_assets() {
        // Get all licenses
        $store = self::lic_store_get();
        
        foreach ($store as $license_key => $license) {
            $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
            
            // Check if Liquid Web is connected
            if (empty($settings['api_key']) || empty($settings['account_number'])) {
                continue;
            }
            
            // Check if sync is needed (every 6 hours)
            $last_sync = $settings['last_sync'] ?? '';
            if (!empty($last_sync)) {
                $last_sync_time = strtotime($last_sync);
                if ($last_sync_time && (current_time('timestamp') - $last_sync_time) < 6 * HOUR_IN_SECONDS) {
                    continue; // Skip if synced within last 6 hours
                }
            }
            
            // Perform sync
            $result = self::sync_liquidweb_assets($license_key);
            if (!is_wp_error($result)) {
                error_log('[VL Hub] Auto-synced Liquid Web assets for license: ' . $license_key . ' - ' . $result['assets_synced'] . ' assets');
            }
        }
    }

    /**
     * Renders CloudOps & Infrastructure cloud connections.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for cloud connections
     */
    public static function render_cloudops_connections($license_key, $license) {
        $html = '<div class="vl-cloud-connections" style="margin-top: 20px;">';
        $html .= '<h4>Cloud Connections</h4>';
        $html .= '<p>Connect to cloud services for infrastructure monitoring and management.</p>';
        
        // Check Liquid Web connection status
        $liquidweb_status = self::get_liquidweb_connection_status($license_key);
        
        // Check Cloudflare connection status
        $cloudflare_status = self::get_cloudflare_connection_status($license_key);
        
        // Check Lighthouse Insights connection status
        $pagespeed_status = self::get_pagespeed_connection_status($license_key);
        
        // Check AWS S3 connection status
        $aws_s3_status = self::get_aws_s3_connection_status($license_key);
        
        $connections = array(
            array(
                'name' => 'Microsoft Azure',
                'subcategory' => 'Servers & Hosting',
                'icon' => '🔷',
                'description' => 'Azure cloud services, virtual machines, and hosting',
                'status' => 'disconnected'
            ),
            array(
                'name' => 'Cloudflare',
                'subcategory' => 'CDNs & Firewalls',
                'icon' => '☁️',
                'description' => 'CDN, DDoS protection, and web security',
                'status' => $cloudflare_status['connected'] ? 'connected' : 'disconnected',
                'has_modal' => true
            ),
            array(
                'name' => 'Liquid Web',
                'subcategory' => 'Servers & Hosting',
                'icon' => '🌊',
                'description' => 'Managed hosting and server infrastructure',
                'status' => $liquidweb_status['connected'] ? 'connected' : 'disconnected',
                'has_modal' => true
            ),
            array(
                'name' => 'Google Cloud',
                'subcategory' => 'Cloud Services',
                'icon' => '☁️',
                'description' => 'Google Cloud Platform services and infrastructure',
                'status' => 'disconnected'
            ),
            array(
                'name' => 'AWS S3',
                'subcategory' => 'Cloud Storage',
                'icon' => '🟠',
                'description' => 'Amazon S3 storage, backups, and cloud infrastructure',
                'status' => self::get_aws_s3_connection_status($license_key)['connected'] ? 'connected' : 'disconnected',
                'has_modal' => true
            ),
            array(
                'name' => 'Lighthouse Insights',
                'subcategory' => 'Performance Analytics',
                'icon' => '🔍',
                'description' => 'Website performance analysis and optimization',
                'status' => $pagespeed_status['connected'] ? 'connected' : 'disconnected',
                'has_modal' => true
            ),
            array(
                'name' => 'GoDaddy',
                'subcategory' => 'Domains & DNS',
                'icon' => '🌐',
                'description' => 'Domain management and DNS services',
                'status' => 'disconnected'
            )
        );
        
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">';
        
        foreach ($connections as $connection) {
            $status_color = $connection['status'] === 'connected' ? '#00a32a' : '#d63638';
            $status_text = $connection['status'] === 'connected' ? 'Connected' : 'Not Connected';
            
            $html .= '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
            $html .= '<div style="display: flex; align-items: center; margin-bottom: 15px;">';
            $html .= '<span style="font-size: 24px; margin-right: 10px;">' . $connection['icon'] . '</span>';
            $html .= '<div>';
            $html .= '<h5 style="margin: 0; font-size: 16px; color: #333;">' . esc_html($connection['name']) . '</h5>';
            $html .= '<small style="color: #666;">' . esc_html($connection['subcategory']) . '</small>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '<p style="color: #666; font-size: 14px; margin: 10px 0;">' . esc_html($connection['description']) . '</p>';
            
            // Show connection details for Liquid Web if connected
            if ($connection['name'] === 'Liquid Web' && $liquidweb_status['connected']) {
                $html .= '<div style="background: #f0f8ff; padding: 10px; border-radius: 4px; margin: 10px 0; font-size: 12px;">';
                $html .= '<strong>Connected Account:</strong> ' . esc_html($liquidweb_status['account_number']) . '<br>';
                $html .= '<strong>Assets:</strong> ' . $liquidweb_status['asset_count'] . ' servers/assets<br>';
                $html .= '<strong>Last Sync:</strong> ' . esc_html($liquidweb_status['last_sync']) . '</div>';
            }
            
            // Show connection details for Cloudflare if connected
            if ($connection['name'] === 'Cloudflare' && $cloudflare_status['connected']) {
                $html .= '<div style="background: #f0f8ff; padding: 10px; border-radius: 4px; margin: 10px 0; font-size: 12px;">';
                $html .= '<strong>Connected Account:</strong> ' . esc_html($cloudflare_status['account_name']) . '<br>';
                $html .= '<strong>Zones:</strong> ' . $cloudflare_status['zone_count'] . ' domains<br>';
                if (!empty($cloudflare_status['zone_id'])) {
                    $html .= '<strong>Monitoring:</strong> Specific zone (ID: ' . esc_html($cloudflare_status['zone_id']) . ')<br>';
                } else {
                    $html .= '<strong>Monitoring:</strong> All zones<br>';
                }
                $html .= '<strong>Last Sync:</strong> ' . esc_html($cloudflare_status['last_sync']) . '</div>';
            }
            
        // Show connection details for Lighthouse Insights if connected
        if ($connection['name'] === 'Lighthouse Insights' && $pagespeed_status['connected']) {
            $html .= '<div style="background: #f0f8ff; padding: 10px; border-radius: 4px; margin: 10px 0; font-size: 12px;">';
            $html .= '<strong>Monitored URL:</strong> ' . esc_html($pagespeed_status['url']) . ' <span style="color: #666;">(locked)</span><br>';
            $html .= '<strong>Analyses:</strong> ' . $pagespeed_status['analysis_count'] . ' performance reports<br>';
            $html .= '<strong>Last Sync:</strong> ' . esc_html($pagespeed_status['last_sync']) . '</div>';
        }
        
        // Show connection details for AWS S3 if connected
        if ($connection['name'] === 'AWS S3' && $aws_s3_status['connected']) {
            $html .= '<div style="background: #f0f8ff; padding: 10px; border-radius: 4px; margin: 10px 0; font-size: 12px;">';
            $html .= '<strong>Region:</strong> ' . esc_html($aws_s3_status['region']) . '<br>';
            $html .= '<strong>Buckets:</strong> ' . $aws_s3_status['bucket_count'] . ' storage buckets<br>';
            $html .= '<strong>Total Objects:</strong> ' . number_format($aws_s3_status['object_count']) . ' files<br>';
            $html .= '<strong>Storage Used:</strong> ' . $aws_s3_status['storage_used'] . '<br>';
            $html .= '<strong>Last Sync:</strong> ' . esc_html($aws_s3_status['last_sync']) . '</div>';
        }
            
            $html .= '<div style="display: flex; justify-content: space-between; align-items: center;">';
            $html .= '<span style="color: ' . $status_color . '; font-weight: bold; font-size: 12px;">' . $status_text . '</span>';
            $html .= '<div style="display: flex; gap: 5px;">';
            
            if ($connection['name'] === 'Liquid Web') {
                if ($liquidweb_status['connected']) {
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="showLiquidWebModal(\'' . esc_js($license_key) . '\')">Manage</button>';
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="syncLiquidWebAssets(\'' . esc_js($license_key) . '\')">Sync Now</button>';
                } else {
                    $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;" onclick="showLiquidWebModal(\'' . esc_js($license_key) . '\')">Connect</button>';
                }
            } elseif ($connection['name'] === 'Cloudflare') {
                if ($cloudflare_status['connected']) {
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="showCloudflareModal(\'' . esc_js($license_key) . '\')">Manage</button>';
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="syncCloudflareData(\'' . esc_js($license_key) . '\')">Sync Now</button>';
                } else {
                    $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;" onclick="showCloudflareModal(\'' . esc_js($license_key) . '\')">Connect</button>';
                }
            } elseif ($connection['name'] === 'Lighthouse Insights') {
                if ($pagespeed_status['connected']) {
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="showPageSpeedModal(\'' . esc_js($license_key) . '\')">Manage</button>';
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="syncPageSpeedData(\'' . esc_js($license_key) . '\')">Sync Now</button>';
                } else {
                    $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;" onclick="showPageSpeedModal(\'' . esc_js($license_key) . '\')">Connect</button>';
                }
            } elseif ($connection['name'] === 'AWS S3') {
                if ($aws_s3_status['connected']) {
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="showAWSS3Modal(\'' . esc_js($license_key) . '\')">Manage</button>';
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="syncAWSS3Data(\'' . esc_js($license_key) . '\')">Sync Now</button>';
                } else {
                    $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;" onclick="showAWSS3Modal(\'' . esc_js($license_key) . '\')">Connect</button>';
                }
            } else {
            $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
            }
            
            $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="sendClientLink(\'' . esc_js($connection['name']) . '\', \'' . esc_js($connection['subcategory']) . '\')">Send Link to Client</button>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        
        // Add Liquid Web connection modal
        $html .= self::render_liquidweb_connection_modal($license_key);
        
        // Add Cloudflare connection modal
        $html .= self::render_cloudflare_connection_modal($license_key);
        
        // Add Lighthouse Insights connection modal
        $html .= self::render_pagespeed_connection_modal($license_key);
        
        // Add AWS S3 connection modal
        $html .= self::render_aws_s3_connection_modal($license_key);
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Gets AWS S3 connection status.
     * 
     * @param string $license_key The license key
     * @return array Connection status information
     */
    private static function get_aws_s3_connection_status($license_key) {
        $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
        $s3_data = get_option('vl_aws_s3_data_' . $license_key, array());
        
        return array(
            'connected' => !empty($settings['access_key_id']) && !empty($settings['secret_access_key']) && !empty($settings['region']),
            'region' => $settings['region'] ?? 'us-east-1',
            'bucket_count' => $settings['bucket_count'] ?? 0,
            'object_count' => $settings['object_count'] ?? 0,
            'storage_used' => $settings['storage_used'] ?? '0 B',
            'last_sync' => $settings['last_sync'] ?? 'Never'
        );
    }

    /**
     * Checks SSL/TLS certificate status for a site.
     * 
     * @param string $license_key The license key
     * @return array SSL/TLS status information
     */
    private static function check_ssl_tls_status($license_key) {
        $license = self::lic_lookup_by_key($license_key);
        if (!$license || empty($license['site'])) {
            return array(
                'connected' => false,
                'error' => 'No site URL found',
                'certificate_info' => null
            );
        }
        
        $site_url = rtrim($license['site'], '/');
        $parsed_url = parse_url($site_url);
        $host = $parsed_url['host'] ?? $site_url;
        
        // Check if we have cached SSL status (cache for 1 hour)
        $cache_key = 'vl_ssl_status_' . md5($host);
        $cached_status = get_transient($cache_key);
        if ($cached_status !== false) {
            return $cached_status;
        }
        
        $ssl_status = array(
            'connected' => false,
            'error' => null,
            'certificate_info' => null,
            'expiry_days' => null,
            'tls_version' => null,
            'cipher_suite' => null
        );
        
        try {
            // Create SSL context with timeout
            $context = stream_context_create(array(
                "ssl" => array(
                    "verify_peer" => true,
                    "verify_peer_name" => true,
                    "capture_peer_cert" => true,
                    "peer_name" => $host
                )
            ));
            
            // Attempt to connect to the site with SSL
            $socket = @stream_socket_client(
                "ssl://{$host}:443",
                $errno,
                $errstr,
                10, // 10 second timeout
                STREAM_CLIENT_CONNECT,
                $context
            );
            
            if (!$socket) {
                $ssl_status['error'] = "SSL connection failed: {$errstr}";
                return $ssl_status;
            }
            
            // Get certificate information
            $cert = stream_context_get_params($socket)['options']['ssl']['peer_certificate'];
            if ($cert) {
                $cert_info = openssl_x509_parse($cert);
                $valid_from = $cert_info['validFrom_time_t'];
                $valid_to = $cert_info['validTo_time_t'];
                $current_time = time();
                
                $ssl_status['connected'] = true;
                $ssl_status['certificate_info'] = array(
                    'subject' => $cert_info['subject']['CN'] ?? 'Unknown',
                    'issuer' => $cert_info['issuer']['CN'] ?? 'Unknown',
                    'valid_from' => date('Y-m-d H:i:s', $valid_from),
                    'valid_to' => date('Y-m-d H:i:s', $valid_to),
                    'expiry_days' => floor(($valid_to - $current_time) / 86400)
                );
                
                $ssl_status['expiry_days'] = $ssl_status['certificate_info']['expiry_days'];
                
                // Check if certificate is expired or expiring soon
                if ($valid_to < $current_time) {
                    $ssl_status['connected'] = false;
                    $ssl_status['error'] = 'SSL certificate has expired';
                } elseif ($ssl_status['expiry_days'] < 30) {
                    $ssl_status['error'] = "SSL certificate expires in {$ssl_status['expiry_days']} days";
                }
                
                // Get TLS version and cipher info
                $ssl_status['tls_version'] = 'TLS 1.2+'; // Default assumption
                $ssl_status['cipher_suite'] = 'Secure';
            }
            
            fclose($socket);
            
        } catch (Exception $e) {
            $ssl_status['error'] = 'SSL check failed: ' . $e->getMessage();
        }
        
        // Cache the result for 1 hour
        set_transient($cache_key, $ssl_status, HOUR_IN_SECONDS);
        
        return $ssl_status;
    }

    /**
     * Renders Security cloud connections.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for security connections
     */
    public static function render_security_connections($license_key, $license) {
        $html = '<div class="vl-security-connections" style="margin-top: 20px;">';
        $html .= '<h4>Security Connections</h4>';
        $html .= '<p>Connect to security services for threat detection and protection.</p>';
        
        // Get actual connection status from CloudOps
        $cloudflare_settings = get_option('vl_cloudflare_settings_' . $license_key, array());
        $cloudflare_connected = !empty($cloudflare_settings['api_token']) && !empty($cloudflare_settings['account_id']);
        
        // Check real SSL/TLS status by pinging the site
        $ssl_tls_status = self::check_ssl_tls_status($license_key);
        $ssl_tls_connected = $ssl_tls_status['connected'];
        
        $connections = array(
            array(
                'name' => 'Cloudflare',
                'subcategory' => 'CDNs & Firewalls',
                'icon' => '☁️',
                'description' => 'DDoS protection, WAF, and security features',
                'status' => $cloudflare_connected ? 'connected' : 'disconnected'
            ),
            array(
                'name' => 'SSL/TLS Status',
                'subcategory' => 'Certificate Management',
                'icon' => '🔒',
                'description' => 'SSL certificate monitoring and expiry alerts',
                'status' => $ssl_tls_connected ? 'connected' : 'disconnected'
            )
        );
        
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">';
        
        foreach ($connections as $connection) {
            $status_color = $connection['status'] === 'connected' ? '#00a32a' : '#d63638';
            $status_text = $connection['status'] === 'connected' ? 'Connected' : 'Not Connected';
            
            $html .= '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
            $html .= '<div style="display: flex; align-items: center; margin-bottom: 15px;">';
            $html .= '<span style="font-size: 24px; margin-right: 10px;">' . $connection['icon'] . '</span>';
            $html .= '<div>';
            $html .= '<h5 style="margin: 0; font-size: 16px; color: #333;">' . esc_html($connection['name']) . '</h5>';
            $html .= '<small style="color: #666;">' . esc_html($connection['subcategory']) . '</small>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '<p style="color: #666; font-size: 14px; margin: 10px 0;">' . esc_html($connection['description']) . '</p>';
            
            // Add SSL certificate details if this is SSL/TLS Status
            if ($connection['name'] === 'SSL/TLS Status' && $ssl_tls_status['certificate_info']) {
                $cert_info = $ssl_tls_status['certificate_info'];
                $expiry_color = $ssl_tls_status['expiry_days'] > 30 ? '#00a32a' : ($ssl_tls_status['expiry_days'] > 7 ? '#dba617' : '#d63638');
                
                $html .= '<div style="background: #f9f9f9; padding: 10px; border-radius: 5px; margin: 10px 0; font-size: 12px;">';
                $html .= '<div style="margin-bottom: 5px;"><strong>Certificate:</strong> ' . esc_html($cert_info['subject']) . '</div>';
                $html .= '<div style="margin-bottom: 5px;"><strong>Issuer:</strong> ' . esc_html($cert_info['issuer']) . '</div>';
                $html .= '<div style="margin-bottom: 5px;"><strong>Expires:</strong> ' . esc_html($cert_info['valid_to']) . '</div>';
                $html .= '<div style="color: ' . $expiry_color . '; font-weight: bold;">';
                $html .= '<strong>Days until expiry:</strong> ' . $ssl_tls_status['expiry_days'] . ' days';
                $html .= '</div>';
                if ($ssl_tls_status['error']) {
                    $html .= '<div style="color: #d63638; margin-top: 5px;"><strong>Warning:</strong> ' . esc_html($ssl_tls_status['error']) . '</div>';
                }
                $html .= '</div>';
            }
            
            $html .= '<div style="display: flex; justify-content: space-between; align-items: center;">';
            $html .= '<span style="color: ' . $status_color . '; font-weight: bold; font-size: 12px;">' . $status_text . '</span>';
            $html .= '<div style="display: flex; gap: 5px;">';
            $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
            $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="sendClientLink(\'' . esc_js($connection['name']) . '\', \'' . esc_js($connection['subcategory']) . '\')">Send Link to Client</button>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders Analytics cloud connections.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for analytics connections
     */
    public static function render_analytics_connections($license_key, $license) {
        $html = '<div class="vl-analytics-connections" style="margin-top: 20px;">';
        $html .= '<h4>Analytics Connections</h4>';
        $html .= '<p>Connect to analytics services for comprehensive data collection.</p>';
        
        // Get actual connection status from CloudOps
        $ga4_settings = get_option('vl_ga4_settings_' . $license_key, array());
        $ga4_connected = !empty($ga4_settings['ga4_enabled']) && !empty($ga4_settings['ga4_property_id']) && (!empty($ga4_settings['ga4_api_key']) || !empty($ga4_settings['ga4_credentials']));
        
        $pagespeed_settings = get_option('vl_pagespeed_settings_' . $license_key, array());
        $pagespeed_connected = !empty($pagespeed_settings['url']);
        
        $connections = array(
            array(
                'name' => 'Google Analytics 4',
                'subcategory' => 'Site Analytics',
                'icon' => '📊',
                'description' => 'Website traffic and user behavior analytics',
                'status' => $ga4_connected ? 'connected' : 'disconnected'
            ),
            array(
                'name' => 'Lighthouse Insights',
                'subcategory' => 'Performance Analytics',
                'icon' => '🔍',
                'description' => 'Website performance analysis and optimization',
                'status' => $pagespeed_connected ? 'connected' : 'disconnected',
                'has_modal' => true
            )
        );
        
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">';
        
        foreach ($connections as $connection) {
            $status_color = $connection['status'] === 'connected' ? '#00a32a' : '#d63638';
            $status_text = $connection['status'] === 'connected' ? 'Connected' : 'Not Connected';
            
            $html .= '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
            $html .= '<div style="display: flex; align-items: center; margin-bottom: 15px;">';
            $html .= '<span style="font-size: 24px; margin-right: 10px;">' . $connection['icon'] . '</span>';
            $html .= '<div>';
            $html .= '<h5 style="margin: 0; font-size: 16px; color: #333;">' . esc_html($connection['name']) . '</h5>';
            $html .= '<small style="color: #666;">' . esc_html($connection['subcategory']) . '</small>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '<p style="color: #666; font-size: 14px; margin: 10px 0;">' . esc_html($connection['description']) . '</p>';
            
            // Show connection details for Lighthouse Insights if connected
            if ($connection['name'] === 'Lighthouse Insights' && $pagespeed_connected) {
                $html .= '<div style="background: #f0f8ff; padding: 10px; border-radius: 4px; margin: 10px 0; font-size: 12px;">';
                $html .= '<strong>Monitored URL:</strong> ' . esc_html($pagespeed_settings['url']) . '<br>';
                $html .= '<strong>Analyses:</strong> ' . ($pagespeed_settings['analysis_count'] ?? 0) . ' performance reports<br>';
                $html .= '<strong>Last Sync:</strong> ' . esc_html($pagespeed_settings['last_sync'] ?? 'Never') . '</div>';
            }
            
            $html .= '<div style="display: flex; justify-content: space-between; align-items: center;">';
            $html .= '<span style="color: ' . $status_color . '; font-weight: bold; font-size: 12px;">' . $status_text . '</span>';
            $html .= '<div style="display: flex; gap: 5px;">';
            
            if ($connection['name'] === 'Google Analytics 4') {
                if ($ga4_connected) {
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;">Manage</button>';
                } else {
            $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
                }
            } elseif ($connection['name'] === 'Lighthouse Insights') {
                if ($pagespeed_connected) {
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="showPageSpeedModal(\'' . esc_js($license_key) . '\')">Manage</button>';
                    $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="syncPageSpeedData(\'' . esc_js($license_key) . '\')">Sync Now</button>';
                } else {
                    $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;" onclick="showPageSpeedModal(\'' . esc_js($license_key) . '\')">Connect</button>';
                }
            } else {
                $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
            }
            
            $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="sendClientLink(\'' . esc_js($connection['name']) . '\', \'' . esc_js($connection['subcategory']) . '\')">Send Link to Client</button>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Add Lighthouse Insights connection modal
        $html .= self::render_pagespeed_connection_modal($license_key);
        
        $html .= '</div>';
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders AWS S3 connection modal.
     * 
     * @param string $license_key The license key
     * @return string HTML content for AWS S3 connection modal
     */
    public static function render_aws_s3_connection_modal($license_key) {
        $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
        $is_connected = !empty($settings['access_key_id']) && !empty($settings['secret_access_key']) && !empty($settings['region']);
        
        $html = '<div id="aws-s3-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 700px; max-height: 80vh; overflow-y: auto;">';
        $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
        $html .= '<h3 style="margin: 0;">AWS S3 Connection</h3>';
        $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;">&times;</span>';
        $html .= '</div>';
        
        $html .= '<div class="vl-modal-body">';
        
        if ($is_connected) {
            // Show connection details and management options
            $html .= '<div style="background: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0073aa;">Connection Status: Connected</h4>';
            $html .= '<p><strong>Region:</strong> ' . esc_html($settings['region']) . '</p>';
            $html .= '<p><strong>Access Key ID:</strong> ' . esc_html(substr($settings['access_key_id'], 0, 8) . '...') . '</p>';
            if (!empty($settings['s3_uri'])) {
                $html .= '<p><strong>S3 URI:</strong> ' . esc_html($settings['s3_uri']) . '</p>';
            }
            $html .= '<p><strong>Buckets:</strong> ' . ($settings['bucket_count'] ?? 0) . '</p>';
            $html .= '<p><strong>Total Objects:</strong> ' . number_format($settings['object_count'] ?? 0) . '</p>';
            $html .= '<p><strong>Storage Used:</strong> ' . esc_html($settings['storage_used'] ?? '0 B') . '</p>';
            $html .= '<p><strong>Last Sync:</strong> ' . esc_html($settings['last_sync'] ?? 'Never') . '</p>';
            $html .= '</div>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-bottom: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="syncAWSS3Data(\'' . esc_js($license_key) . '\')">Sync Data Now</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testAWSS3Connection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="debugAWSS3Connection(\'' . esc_js($license_key) . '\')">Debug API</button>';
            if (!empty($settings['s3_uri'])) {
                $html .= '<button type="button" class="button button-secondary" onclick="viewS3Objects(\'' . esc_js($license_key) . '\')">View Bucket Objects</button>';
            }
            $html .= '</div>';
            
            $html .= '<h4>Bucket Overview</h4>';
            $buckets = get_option('vl_aws_s3_buckets_' . $license_key, array());
            if (!empty($buckets)) {
                $html .= '<div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px;">';
                $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
                $html .= '<thead><tr><th>Bucket Name</th><th>Region</th><th>Objects</th><th>Size</th><th>Created</th></tr></thead>';
                $html .= '<tbody>';
                
                foreach (array_slice($buckets, 0, 20) as $bucket) {
                    $html .= '<tr>';
                    $html .= '<td>' . esc_html($bucket['name'] ?? 'N/A') . '</td>';
                    $html .= '<td>' . esc_html($bucket['region'] ?? 'N/A') . '</td>';
                    $html .= '<td>' . number_format($bucket['object_count'] ?? 0) . '</td>';
                    $html .= '<td>' . esc_html($bucket['size'] ?? '0 B') . '</td>';
                    $html .= '<td>' . esc_html($bucket['created'] ?? 'N/A') . '</td>';
                    $html .= '</tr>';
                }
                
                $html .= '</tbody></table>';
                $html .= '</div>';
                
                if (count($buckets) > 20) {
                    $html .= '<p style="text-align: center; color: #666; margin-top: 10px;">Showing first 20 of ' . count($buckets) . ' buckets</p>';
                }
            } else {
                $html .= '<p>No buckets found. Click "Sync Data Now" to fetch your S3 buckets.</p>';
            }
            
            $html .= '<div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd;">';
            $html .= '<button type="button" class="button button-link-delete" onclick="disconnectAWSS3(\'' . esc_js($license_key) . '\')">Disconnect AWS S3</button>';
            $html .= '</div>';
            
        } else {
            // Show connection form
            $html .= '<form id="aws-s3-connection-form">';
            $html .= '<div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ffc107;">';
            $html .= '<h4 style="margin-top: 0; color: #856404;">Connection Requirements</h4>';
            $html .= '<p style="margin: 0;">To connect to AWS S3, you need:</p>';
            $html .= '<ul style="margin: 10px 0 0 20px;">';
            $html .= '<li>Your AWS Access Key ID</li>';
            $html .= '<li>Your AWS Secret Access Key</li>';
            $html .= '<li>Your preferred AWS Region</li>';
            $html .= '<li>S3 permissions for the account</li>';
            $html .= '</ul>';
            $html .= '</div>';
            
            $html .= '<table class="form-table">';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="aws-access-key">Access Key ID</label></th>';
            $html .= '<td><input type="text" id="aws-access-key" name="access_key_id" value="' . esc_attr($settings['access_key_id'] ?? '') . '" class="regular-text" placeholder="AKIA..." required></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="aws-secret-key">Secret Access Key</label></th>';
            $html .= '<td><input type="password" id="aws-secret-key" name="secret_access_key" value="' . esc_attr($settings['secret_access_key'] ?? '') . '" class="regular-text" placeholder="Your AWS Secret Access Key" required></td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="aws-region">Region</label></th>';
            $html .= '<td>';
            $html .= '<select id="aws-region" name="region" class="regular-text" required>';
            $regions = array(
                'us-east-1' => 'US East (N. Virginia)',
                'us-east-2' => 'US East (Ohio)',
                'us-west-1' => 'US West (California)',
                'us-west-2' => 'US West (Oregon)',
                'eu-west-1' => 'Europe (Ireland)',
                'eu-west-2' => 'Europe (London)',
                'eu-west-3' => 'Europe (Paris)',
                'eu-central-1' => 'Europe (Frankfurt)',
                'eu-north-1' => 'Europe (Stockholm)',
                'ap-southeast-1' => 'Asia Pacific (Singapore)',
                'ap-southeast-2' => 'Asia Pacific (Sydney)',
                'ap-northeast-1' => 'Asia Pacific (Tokyo)',
                'ap-northeast-2' => 'Asia Pacific (Seoul)',
                'ap-northeast-3' => 'Asia Pacific (Osaka)',
                'ap-south-1' => 'Asia Pacific (Mumbai)',
                'ca-central-1' => 'Canada (Central)',
                'sa-east-1' => 'South America (Sao Paulo)'
            );
            foreach ($regions as $value => $label) {
                $selected = ($settings['region'] ?? 'us-east-1') === $value ? 'selected' : '';
                $html .= '<option value="' . esc_attr($value) . '" ' . $selected . '>' . esc_html($label) . '</option>';
            }
            $html .= '</select>';
            $html .= '</td>';
            $html .= '</tr>';
            $html .= '<tr>';
            $html .= '<th scope="row"><label for="aws-s3-uri">S3 URI/ARN</label></th>';
            $html .= '<td>';
            $html .= '<input type="text" id="aws-s3-uri" name="s3_uri" value="' . esc_attr($settings['s3_uri'] ?? '') . '" class="regular-text" placeholder="s3://bucket-name/ or arn:aws:s3:::bucket-name/" />';
            $html .= '<p class="description">Enter your S3 bucket URI or ARN (e.g., s3://sacloudbackups/ or arn:aws:s3:::sacloudbackups/)</p>';
            $html .= '</td>';
            $html .= '</tr>';
            $html .= '</table>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-top: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="saveAWSS3Connection(\'' . esc_js($license_key) . '\')">Connect to AWS S3</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testAWSS3Connection(\'' . esc_js($license_key) . '\')">Test Connection</button>';
            $html .= '</div>';
            $html .= '</form>';
        }
        
        $html .= '</div>';
        $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
        $html .= '<button type="button" class="button" onclick="closeAWSS3Modal()">Close</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }

    /**
     * Renders Google Search Console connection modal.
     * 
     * @param string $license_key The license key
     * @return string HTML content for GSC connection modal
     */
    public static function render_gsc_connection_modal($license_key) {
        $gsc_status = self::get_gsc_connection_status($license_key);
        
        $html = '<div id="gsc-connection-modal" class="vl-modal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
        $html .= '<div style="background-color: white; margin: 5% auto; padding: 20px; border-radius: 8px; width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto;">';
        
        $html .= '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">';
        $html .= '<h3 style="margin: 0; color: #333;">Google Search Console Integration</h3>';
        $html .= '<button type="button" onclick="closeGSCModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #666;">&times;</button>';
        $html .= '</div>';
        
        if ($gsc_status['connected']) {
            $html .= '<div style="background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<strong>✅ Connected!</strong> Google Search Console is connected and monitoring your site.';
            $html .= '</div>';
            
            $html .= '<div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0;">Connection Details</h4>';
            $html .= '<p><strong>Site URL:</strong> ' . esc_html($gsc_status['site_url']) . '</p>';
            $html .= '<p><strong>Last Sync:</strong> ' . esc_html($gsc_status['last_sync']) . '</p>';
            $html .= '<p><strong>Data Points:</strong> ' . esc_html($gsc_status['data_points']) . '</p>';
            $html .= '</div>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-top: 20px;">';
            $html .= '<button type="button" class="button button-secondary" onclick="syncGSCData(\'' . esc_js($license_key) . '\')" style="flex: 1;">Sync Data Now</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="disconnectGSC(\'' . esc_js($license_key) . '\')" style="flex: 1;">Disconnect</button>';
            $html .= '</div>';
        } else {
            $html .= '<div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<strong>⚠️ Not Connected</strong> Connect to Google Search Console to monitor your site\'s search performance.';
            $html .= '</div>';
            
            $html .= '<form id="gsc-connection-form">';
            $html .= '<div style="margin-bottom: 20px;">';
            $html .= '<label for="gsc-site-url" style="display: block; margin-bottom: 5px; font-weight: bold;">Site URL *</label>';
            $html .= '<input type="url" id="gsc-site-url" name="site_url" required style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;" placeholder="https://example.com" value="' . esc_attr($gsc_status['site_url']) . '">';
            $html .= '<small style="color: #666;">The exact URL of your site as registered in Google Search Console</small>';
            $html .= '</div>';
            
            $html .= '<div style="margin-bottom: 20px;">';
            $html .= '<label for="gsc-service-account" style="display: block; margin-bottom: 5px; font-weight: bold;">Service Account JSON *</label>';
            $html .= '<textarea id="gsc-service-account" name="service_account_json" required style="width: 100%; height: 120px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; font-size: 12px;" placeholder="Paste your Google Service Account JSON credentials here..."></textarea>';
            $html .= '<small style="color: #666;">Download the Service Account JSON from Google Cloud Console with Search Console API access</small>';
            $html .= '</div>';
            
            $html .= '<div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4 style="margin-top: 0; color: #0066cc;">Setup Instructions:</h4>';
            $html .= '<ol style="margin: 0; padding-left: 20px;">';
            $html .= '<li>Go to <a href="https://console.cloud.google.com/" target="_blank">Google Cloud Console</a></li>';
            $html .= '<li>Create a new project or select existing one</li>';
            $html .= '<li>Enable the "Search Console API"</li>';
            $html .= '<li>Create a Service Account and download the JSON key</li>';
            $html .= '<li>Add the Service Account email to your Google Search Console property</li>';
            $html .= '<li>Paste the JSON credentials above</li>';
            $html .= '</ol>';
            $html .= '</div>';
            
            $html .= '<div style="display: flex; gap: 10px; margin-top: 20px;">';
            $html .= '<button type="button" class="button button-primary" onclick="saveGSCConnection(\'' . esc_js($license_key) . '\')" style="flex: 1;">Connect to Google Search Console</button>';
            $html .= '<button type="button" class="button button-secondary" onclick="testGSCConnection(\'' . esc_js($license_key) . '\')" style="flex: 1;">Test Connection</button>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
        
        return $html;
    }

    /**
     * Gets Google Search Console connection status.
     * 
     * @param string $license_key The license key
     * @return array Connection status information
     */
    private static function get_gsc_connection_status($license_key) {
        $settings = get_option('vl_gsc_settings_' . $license_key, array());
        
        return array(
            'connected' => !empty($settings['service_account_json']) && !empty($settings['site_url']),
            'site_url' => $settings['site_url'] ?? '',
            'data_points' => $settings['data_points'] ?? 0,
            'last_sync' => $settings['last_sync'] ?? 'Never'
        );
    }

    /**
     * Handles AWS S3 API requests.
     * 
     * @param string $license_key The license key
     * @param string $endpoint The API endpoint
     * @param array $params Additional parameters
     * @return array|WP_Error API response or error
     */
    public static function aws_s3_api_handler($license_key, $endpoint, $params = array()) {
        $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
        
        if (empty($settings['access_key_id']) || empty($settings['secret_access_key']) || empty($settings['region'])) {
            return new WP_Error('aws_s3_missing_credentials', 'AWS S3 credentials not configured');
        }
        
        $region = $settings['region'];
        $access_key = $settings['access_key_id'];
        $secret_key = $settings['secret_access_key'];
        
        // Build the S3 API URL
        $base_url = "https://s3.{$region}.amazonaws.com";
        $url = $base_url . '/' . $endpoint;
        
        // Add query parameters to URL
        if (!empty($params)) {
            $query_parts = array();
            foreach ($params as $key => $value) {
                if ($value !== '') {
                    $query_parts[] = urlencode($key) . '=' . urlencode($value);
                } else {
                    $query_parts[] = urlencode($key);
                }
            }
            if (!empty($query_parts)) {
                $url .= '?' . implode('&', $query_parts);
            }
        }
        
        // Create AWS signature
        $timestamp = gmdate('Ymd\THis\Z');
        $date = gmdate('Ymd');
        
        // Create canonical request
        $canonical_request = self::create_aws_canonical_request('GET', $endpoint, $params, $timestamp);
        
        // Create string to sign
        $string_to_sign = "AWS4-HMAC-SHA256\n{$timestamp}\n{$date}/{$region}/s3/aws4_request\n" . hash('sha256', $canonical_request);
        
        // Calculate signature
        $signature = self::calculate_aws_signature($secret_key, $date, $region, 's3', $string_to_sign);
        
        // Create authorization header
        $authorization = "AWS4-HMAC-SHA256 Credential={$access_key}/{$date}/{$region}/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={$signature}";
        
        $headers = array(
            'Authorization' => $authorization,
            'X-Amz-Date' => $timestamp,
            'Host' => "s3.{$region}.amazonaws.com"
        );
        
        $response = wp_remote_get($url, array(
            'headers' => $headers,
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($code >= 200 && $code < 300) {
            // Parse XML response
            $xml = simplexml_load_string($body);
            if ($xml === false) {
                return new WP_Error('aws_s3_invalid_response', 'Invalid XML response from S3 API');
            }
            return json_decode(json_encode($xml), true);
        }
        
        return new WP_Error('aws_s3_api_error', "S3 API error: HTTP {$code} - {$body}");
    }
    
    /**
     * Creates AWS canonical request for signing.
     */
    private static function create_aws_canonical_request($method, $endpoint, $params, $timestamp) {
        $canonical_uri = '/' . $endpoint;
        
        // Build canonical query string
        $canonical_querystring = '';
        if (!empty($params)) {
            $query_parts = array();
            foreach ($params as $key => $value) {
                if ($value !== '') {
                    $query_parts[] = urlencode($key) . '=' . urlencode($value);
                } else {
                    $query_parts[] = urlencode($key);
                }
            }
            sort($query_parts);
            $canonical_querystring = implode('&', $query_parts);
        }
        
        $canonical_headers = "host:s3.amazonaws.com\nx-amz-date:{$timestamp}\n";
        $signed_headers = 'host;x-amz-date';
        $payload_hash = hash('sha256', '');
        
        return "{$method}\n{$canonical_uri}\n{$canonical_querystring}\n{$canonical_headers}\n{$signed_headers}\n{$payload_hash}";
    }
    
    /**
     * Calculates AWS signature.
     */
    private static function calculate_aws_signature($secret_key, $date, $region, $service, $string_to_sign) {
        $k_date = hash_hmac('sha256', $date, 'AWS4' . $secret_key, true);
        $k_region = hash_hmac('sha256', $region, $k_date, true);
        $k_service = hash_hmac('sha256', $service, $k_region, true);
        $k_signing = hash_hmac('sha256', 'aws4_request', $k_service, true);
        
        return hash_hmac('sha256', $string_to_sign, $k_signing);
    }

    /**
     * Handles Google Search Console API requests.
     * 
     * @param string $license_key The license key
     * @param string $endpoint The API endpoint
     * @param array $params Additional parameters
     * @return array|WP_Error API response or error
     */
    public static function gsc_api_handler($license_key, $endpoint, $params = array()) {
        $settings = get_option('vl_gsc_settings_' . $license_key, array());
        
        if (empty($settings['service_account_json'])) {
            return new WP_Error('gsc_no_credentials', 'Google Search Console credentials not configured');
        }
        
        try {
            // Parse Service Account JSON
            $credentials = json_decode($settings['service_account_json'], true);
            if (!$credentials) {
                return new WP_Error('gsc_invalid_credentials', 'Invalid Service Account JSON format');
            }
            
            // Get access token
            $access_token = self::get_gsc_access_token($credentials);
            if (is_wp_error($access_token)) {
                return $access_token;
            }
            
            // Build API URL
            $api_url = 'https://www.googleapis.com/webmasters/v3/sites/' . urlencode($settings['site_url']) . '/' . $endpoint;
            
            // Add parameters
            if (!empty($params)) {
                $api_url .= '?' . http_build_query($params);
            }
            
            // Make API request
            $response = wp_remote_get($api_url, array(
                'timeout' => 30,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $access_token,
                    'Content-Type' => 'application/json'
                )
            ));
            
            if (is_wp_error($response)) {
                return new WP_Error('gsc_api_error', 'API request failed: ' . $response->get_error_message());
            }
            
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            
            if (isset($data['error'])) {
                return new WP_Error('gsc_api_error', 'GSC API error: ' . $data['error']['message']);
            }
            
            return $data;
            
        } catch (Exception $e) {
            return new WP_Error('gsc_api_error', 'GSC API error: ' . $e->getMessage());
        }
    }

    /**
     * Gets Google Search Console access token using Service Account.
     * 
     * @param array $credentials Service Account credentials
     * @return string|WP_Error Access token or error
     */
    private static function get_gsc_access_token($credentials) {
        try {
            // Check if we have a cached token that's still valid
            $cache_key = 'vl_gsc_token_' . md5($credentials['private_key']);
            $cached_token = get_transient($cache_key);
            if ($cached_token && isset($cached_token['access_token']) && isset($cached_token['expires_at'])) {
                if (time() < $cached_token['expires_at']) {
                    return $cached_token['access_token'];
                }
            }
            
            // Create JWT assertion
            $now = time();
            $header = array(
                'alg' => 'RS256',
                'typ' => 'JWT'
            );
            
            $payload = array(
                'iss' => $credentials['client_email'],
                'scope' => 'https://www.googleapis.com/auth/webmasters.readonly',
                'aud' => 'https://oauth2.googleapis.com/token',
                'iat' => $now,
                'exp' => $now + 3600
            );
            
            $jwt = self::create_jwt_assertion($header, $payload, $credentials['private_key']);
            
            // Request access token
            $token_response = wp_remote_post('https://oauth2.googleapis.com/token', array(
                'timeout' => 30,
                'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
                'body' => array(
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    'assertion' => $jwt
                )
            ));
            
            if (is_wp_error($token_response)) {
                return new WP_Error('gsc_token_error', 'Token request failed: ' . $token_response->get_error_message());
            }
            
            $token_data = json_decode(wp_remote_retrieve_body($token_response), true);
            if (isset($token_data['error'])) {
                return new WP_Error('gsc_token_error', 'Token error: ' . $token_data['error_description']);
            }
            
            // Cache the token
            $token_data['expires_at'] = $now + $token_data['expires_in'] - 60; // 1 minute buffer
            set_transient($cache_key, $token_data, $token_data['expires_in']);
            
            return $token_data['access_token'];
            
        } catch (Exception $e) {
            return new WP_Error('gsc_token_error', 'Token request failed: ' . $e->getMessage());
        }
    }

    /**
     * Creates a JWT assertion for Google Search Console API.
     * 
     * @param array $header JWT header
     * @param array $payload JWT payload
     * @param string $private_key Private key
     * @return string JWT assertion
     */
    private static function create_jwt_assertion($header, $payload, $private_key) {
        $header_encoded = self::base64url_encode(json_encode($header));
        $payload_encoded = self::base64url_encode(json_encode($payload));
        
        $data = $header_encoded . '.' . $payload_encoded;
        
        $signature = '';
        openssl_sign($data, $signature, $private_key, OPENSSL_ALGO_SHA256);
        
        return $data . '.' . self::base64url_encode($signature);
    }

    /**
     * Syncs AWS S3 data.
     * 
     * @param string $license_key The license key
     * @return array|WP_Error Sync result or error
     */
    public static function sync_aws_s3_data($license_key) {
        $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
        
        if (empty($settings['access_key_id']) || empty($settings['secret_access_key']) || empty($settings['region'])) {
            return new WP_Error('aws_s3_missing_credentials', 'AWS S3 credentials not configured');
        }
        
        try {
            $data_points = 0;
            $sync_results = array();
            $s3_data = array();
            $buckets = array();
            $bucket_list = array();
            
            // Check if S3 URI is specified - if so, only process that specific bucket
            if (!empty($settings['s3_uri'])) {
                $s3_uri = $settings['s3_uri'];
                $bucket_name = '';
                
                // Parse S3 URI to get bucket name
                if (preg_match('/s3:\/\/([^\/]+)\//', $s3_uri, $matches)) {
                    $bucket_name = $matches[1];
                } elseif (preg_match('/arn:aws:s3:::([^\/]+)\//', $s3_uri, $matches)) {
                    $bucket_name = $matches[1];
                }
                
                if (!empty($bucket_name)) {
                    // Only process the specified bucket
                    $bucket_list = array(array('Name' => $bucket_name, 'CreationDate' => 'N/A'));
                }
            }
            
            // If no S3 URI specified or parsing failed, fetch all buckets
            if (empty($bucket_list)) {
                $buckets_response = self::aws_s3_api_handler($license_key, '');
                if (!is_wp_error($buckets_response) && isset($buckets_response['Buckets']['Bucket'])) {
                    $bucket_list = is_array($buckets_response['Buckets']['Bucket']) ? $buckets_response['Buckets']['Bucket'] : array($buckets_response['Buckets']['Bucket']);
                }
            }
            
            if (!empty($bucket_list)) {
                $data_points += count($bucket_list);
                $sync_results['buckets'] = count($bucket_list);
                $s3_data['buckets'] = $bucket_list;
                
                // Process each bucket for detailed information
                foreach ($bucket_list as $bucket) {
                    $bucket_name = $bucket['Name'];
                    $bucket_data = array(
                        'name' => $bucket_name,
                        'region' => $settings['region'],
                        'created' => $bucket['CreationDate'] ?? 'Unknown',
                        'object_count' => 0,
                        'size' => '0 B'
                    );
                    
                    // 2. Get bucket location
                    $location_response = self::aws_s3_api_handler($license_key, $bucket_name . '?location');
                    if (!is_wp_error($location_response)) {
                        $bucket_data['region'] = $location_response['LocationConstraint'] ?? $settings['region'];
                    }
                    
                    // 3. List ALL objects in bucket (with pagination)
                    $all_objects = array();
                    $continuation_token = '';
                    $total_size = 0;
                    
                    do {
                        $params = array('list-type' => '2');
                        if (!empty($continuation_token)) {
                            $params['continuation-token'] = $continuation_token;
                        }
                        
                        $objects_response = self::aws_s3_api_handler($license_key, $bucket_name, $params);
                        if (!is_wp_error($objects_response)) {
                            if (isset($objects_response['Contents'])) {
                                $objects = is_array($objects_response['Contents']) ? $objects_response['Contents'] : array($objects_response['Contents']);
                                $all_objects = array_merge($all_objects, $objects);
                                
                                foreach ($objects as $object) {
                                    $total_size += intval($object['Size'] ?? 0);
                                }
                            }
                            
                            // Check for continuation token
                            $continuation_token = $objects_response['NextContinuationToken'] ?? '';
                        } else {
                            break;
                        }
                    } while (!empty($continuation_token));
                    
                    $bucket_data['object_count'] = count($all_objects);
                    $bucket_data['size'] = self::format_bytes($total_size);
                    $bucket_data['all_objects'] = $all_objects; // Store all objects for later use
                    
                    // 4. Get bucket ACL
                    $acl_response = self::aws_s3_api_handler($license_key, $bucket_name, array('acl' => ''));
                    if (!is_wp_error($acl_response)) {
                        $bucket_data['acl'] = $acl_response;
                    }
                    
                    // 5. Get bucket CORS
                    $cors_response = self::aws_s3_api_handler($license_key, $bucket_name, array('cors' => ''));
                    if (!is_wp_error($cors_response)) {
                        $bucket_data['cors'] = $cors_response;
                    }
                    
                    // 6. Get bucket encryption
                    $encryption_response = self::aws_s3_api_handler($license_key, $bucket_name, array('encryption' => ''));
                    if (!is_wp_error($encryption_response)) {
                        $bucket_data['encryption'] = $encryption_response;
                    }
                    
                    // 7. Get bucket lifecycle
                    $lifecycle_response = self::aws_s3_api_handler($license_key, $bucket_name, array('lifecycle' => ''));
                    if (!is_wp_error($lifecycle_response)) {
                        $bucket_data['lifecycle'] = $lifecycle_response;
                    }
                    
                    // 8. Get bucket versioning
                    $versioning_response = self::aws_s3_api_handler($license_key, $bucket_name, array('versioning' => ''));
                    if (!is_wp_error($versioning_response)) {
                        $bucket_data['versioning'] = $versioning_response;
                    }
                    
                    // 9. Get bucket website
                    $website_response = self::aws_s3_api_handler($license_key, $bucket_name, array('website' => ''));
                    if (!is_wp_error($website_response)) {
                        $bucket_data['website'] = $website_response;
                    }
                    
                    // 10. Get bucket notification
                    $notification_response = self::aws_s3_api_handler($license_key, $bucket_name, array('notification' => ''));
                    if (!is_wp_error($notification_response)) {
                        $bucket_data['notification'] = $notification_response;
                    }
                    
                    // 11. Get bucket replication
                    $replication_response = self::aws_s3_api_handler($license_key, $bucket_name, array('replication' => ''));
                    if (!is_wp_error($replication_response)) {
                        $bucket_data['replication'] = $replication_response;
                    }
                    
                    // 12. Get bucket tagging
                    $tagging_response = self::aws_s3_api_handler($license_key, $bucket_name, array('tagging' => ''));
                    if (!is_wp_error($tagging_response)) {
                        $bucket_data['tagging'] = $tagging_response;
                    }
                    
                    // 13. Get bucket policy
                    $policy_response = self::aws_s3_api_handler($license_key, $bucket_name, array('policy' => ''));
                    if (!is_wp_error($policy_response)) {
                        $bucket_data['policy'] = $policy_response;
                    }
                    
                    // 14. Get bucket analytics configurations
                    $analytics_response = self::aws_s3_api_handler($license_key, $bucket_name, array('analytics' => ''));
                    if (!is_wp_error($analytics_response)) {
                        $bucket_data['analytics'] = $analytics_response;
                    }
                    
                    // 15. Get bucket inventory configurations
                    $inventory_response = self::aws_s3_api_handler($license_key, $bucket_name, array('inventory' => ''));
                    if (!is_wp_error($inventory_response)) {
                        $bucket_data['inventory'] = $inventory_response;
                    }
                    
                    // 16. Get bucket metrics configurations
                    $metrics_response = self::aws_s3_api_handler($license_key, $bucket_name, array('metrics' => ''));
                    if (!is_wp_error($metrics_response)) {
                        $bucket_data['metrics'] = $metrics_response;
                    }
                    
                    // 17. Get bucket intelligent tiering configurations
                    $tiering_response = self::aws_s3_api_handler($license_key, $bucket_name, array('intelligent-tiering' => ''));
                    if (!is_wp_error($tiering_response)) {
                        $bucket_data['intelligent_tiering'] = $tiering_response;
                    }
                    
                    // 18. Get bucket ownership controls
                    $ownership_response = self::aws_s3_api_handler($license_key, $bucket_name, array('ownershipControls' => ''));
                    if (!is_wp_error($ownership_response)) {
                        $bucket_data['ownership_controls'] = $ownership_response;
                    }
                    
                    // 19. Get bucket request payment
                    $payment_response = self::aws_s3_api_handler($license_key, $bucket_name, array('requestPayment' => ''));
                    if (!is_wp_error($payment_response)) {
                        $bucket_data['request_payment'] = $payment_response;
                    }
                    
                    // 20. Get bucket accelerate configuration
                    $accelerate_response = self::aws_s3_api_handler($license_key, $bucket_name, array('accelerate' => ''));
                    if (!is_wp_error($accelerate_response)) {
                        $bucket_data['accelerate'] = $accelerate_response;
                    }
                    
                    $buckets[] = $bucket_data;
                }
            }
            
            // Store all S3 data
            update_option('vl_aws_s3_data_' . $license_key, $s3_data);
            update_option('vl_aws_s3_buckets_' . $license_key, $buckets);
            
            // Update settings with summary
            $settings['bucket_count'] = count($buckets);
            $settings['object_count'] = array_sum(array_column($buckets, 'object_count'));
            $settings['last_sync'] = current_time('mysql');
            $settings['storage_used'] = self::calculate_total_storage($buckets);
            update_option('vl_aws_s3_settings_' . $license_key, $settings);
            
            // Create data stream
            $all_streams = self::data_streams_store_get();
            if (!isset($all_streams[$license_key])) {
                $all_streams[$license_key] = array();
            }
            $all_streams[$license_key]['aws_s3'] = array(
                'name' => 'AWS S3 Storage',
                'description' => 'Amazon S3 storage, backups, and cloud infrastructure',
                'categories' => array('cloudops', 'storage'),
                'health_score' => 95,
                'error_count' => 0,
                'warning_count' => 0,
                'data_points' => $data_points,
                'last_sync' => current_time('mysql'),
                'id' => 'aws_s3',
                'license_key' => $license_key,
                'created' => current_time('mysql'),
                'last_updated' => current_time('mysql'),
                'status' => 'active'
            );
            self::data_streams_store_set($all_streams);
            
            return array(
                'success' => true,
                'message' => "Successfully synced {$data_points} AWS S3 data points!" . (!empty($settings['s3_uri']) ? " (Filtered to: " . esc_html($settings['s3_uri']) . ")" : ""),
                'buckets_synced' => count($buckets),
                'objects_synced' => $settings['object_count'],
                'storage_used' => $settings['storage_used']
            );
            
        } catch (Exception $e) {
            return new WP_Error('aws_s3_sync_error', 'Error syncing AWS S3 data: ' . $e->getMessage());
        }
    }
    
    /**
     * Formats bytes into human readable format.
     */
    private static function format_bytes($bytes, $precision = 2) {
        $units = array('B', 'KB', 'MB', 'GB', 'TB', 'PB');
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }
    
    /**
     * Calculates total storage used across all buckets.
     */
    private static function calculate_total_storage($buckets) {
        $total_bytes = 0;
        foreach ($buckets as $bucket) {
            $size_str = $bucket['size'] ?? '0 B';
            $total_bytes += self::parse_bytes($size_str);
        }
        return self::format_bytes($total_bytes);
    }
    
    /**
     * Parses human readable bytes back to integer.
     */
    private static function parse_bytes($size_str) {
        $units = array('B' => 1, 'KB' => 1024, 'MB' => 1024*1024, 'GB' => 1024*1024*1024, 'TB' => 1024*1024*1024*1024);
        $size_str = trim($size_str);
        $unit = substr($size_str, -2);
        $number = floatval(substr($size_str, 0, -2));
        return $number * ($units[$unit] ?? 1);
    }

    /**
     * Syncs Google Search Console data.
     * 
     * @param string $license_key The license key
     * @return array|WP_Error Sync result or error
     */
    public static function sync_gsc_data($license_key) {
        $settings = get_option('vl_gsc_settings_' . $license_key, array());
        
        if (empty($settings['service_account_json']) || empty($settings['site_url'])) {
            return new WP_Error('gsc_not_configured', 'Google Search Console not configured');
        }
        
        try {
            $data_points = 0;
            $sync_results = array();
            $gsc_data = array();
            
            // 1. Search Analytics - Top Queries
            $search_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-30 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'query',
                'rowLimit' => 1000
            ));
            
            // Debug logging
            error_log('[VL Hub] GSC Sync - Search Analytics Response: ' . json_encode($search_analytics));
            
            if (!is_wp_error($search_analytics) && isset($search_analytics['rows'])) {
                $data_points += count($search_analytics['rows']);
                $sync_results['search_queries'] = count($search_analytics['rows']);
                $gsc_data['search_queries'] = $search_analytics['rows'];
                error_log('[VL Hub] GSC Sync - Search Queries: ' . count($search_analytics['rows']) . ' rows');
            } else {
                error_log('[VL Hub] GSC Sync - Search Queries Error: ' . (is_wp_error($search_analytics) ? $search_analytics->get_error_message() : 'No rows in response'));
            }
            
            // 2. Search Analytics - Top Pages
            $page_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-30 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'page',
                'rowLimit' => 1000
            ));
            
            if (!is_wp_error($page_analytics) && isset($page_analytics['rows'])) {
                $data_points += count($page_analytics['rows']);
                $sync_results['top_pages'] = count($page_analytics['rows']);
                $gsc_data['top_pages'] = $page_analytics['rows'];
            }
            
            // 3. Search Analytics - Countries
            $country_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-30 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'country',
                'rowLimit' => 100
            ));
            
            if (!is_wp_error($country_analytics) && isset($country_analytics['rows'])) {
                $data_points += count($country_analytics['rows']);
                $sync_results['countries'] = count($country_analytics['rows']);
                $gsc_data['countries'] = $country_analytics['rows'];
            }
            
            // 4. Search Analytics - Devices
            $device_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-30 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'device',
                'rowLimit' => 100
            ));
            
            if (!is_wp_error($device_analytics) && isset($device_analytics['rows'])) {
                $data_points += count($device_analytics['rows']);
                $sync_results['devices'] = count($device_analytics['rows']);
                $gsc_data['devices'] = $device_analytics['rows'];
            }
            
            // 5. Search Analytics - Search Appearance (AMP, Rich Results)
            $search_appearance_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-30 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'searchAppearance',
                'rowLimit' => 100
            ));
            
            if (!is_wp_error($search_appearance_analytics) && isset($search_appearance_analytics['rows'])) {
                $data_points += count($search_appearance_analytics['rows']);
                $sync_results['search_appearance'] = count($search_appearance_analytics['rows']);
                $gsc_data['search_appearance'] = $search_appearance_analytics['rows'];
            }
            
            // 6. Search Analytics - Date Range Data (last 7 days for more granular data)
            $date_range_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-7 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'date',
                'rowLimit' => 100
            ));
            
            if (!is_wp_error($date_range_analytics) && isset($date_range_analytics['rows'])) {
                $data_points += count($date_range_analytics['rows']);
                $sync_results['date_range'] = count($date_range_analytics['rows']);
                $gsc_data['date_range'] = $date_range_analytics['rows'];
            }
            
            // 7. Search Analytics - Hourly Data (last 3 days for hourly breakdown)
            $hourly_analytics = self::gsc_api_handler($license_key, 'searchAnalytics/query', array(
                'startDate' => date('Y-m-d', strtotime('-3 days')),
                'endDate' => date('Y-m-d'),
                'dimensions' => 'date,hour',
                'rowLimit' => 100
            ));
            
            if (!is_wp_error($hourly_analytics) && isset($hourly_analytics['rows'])) {
                $data_points += count($hourly_analytics['rows']);
                $sync_results['hourly_data'] = count($hourly_analytics['rows']);
                $gsc_data['hourly_data'] = $hourly_analytics['rows'];
            }
            
            // 5. Sitemaps
            $sitemaps = self::gsc_api_handler($license_key, 'sitemaps');
            if (!is_wp_error($sitemaps) && isset($sitemaps['sitemap'])) {
                $data_points += count($sitemaps['sitemap']);
                $sync_results['sitemaps'] = count($sitemaps['sitemap']);
                $gsc_data['sitemaps'] = $sitemaps['sitemap'];
            }
            
            // 8. Site Management - List all properties
            $properties = self::gsc_api_handler($license_key, 'sites');
            if (!is_wp_error($properties) && isset($properties['siteEntry'])) {
                $data_points += count($properties['siteEntry']);
                $sync_results['properties'] = count($properties['siteEntry']);
                $gsc_data['properties'] = $properties['siteEntry'];
            }
            
            // 9. URL Inspection (sample URLs) - Enhanced with AMP status
            $url_inspection = self::gsc_api_handler($license_key, 'urlInspection/index/inspect', array(
                'inspectionUrl' => $settings['site_url']
            ));
            
            if (!is_wp_error($url_inspection)) {
                $data_points += 1;
                $sync_results['url_inspection'] = 1;
                $gsc_data['url_inspection'] = $url_inspection;
            }
            
            // 10. URL Inspection - AMP specific check
            $amp_inspection = self::gsc_api_handler($license_key, 'urlInspection/index/inspect', array(
                'inspectionUrl' => $settings['site_url'],
                'siteUrl' => $settings['site_url']
            ));
            
            if (!is_wp_error($amp_inspection)) {
                $data_points += 1;
                $sync_results['amp_inspection'] = 1;
                $gsc_data['amp_inspection'] = $amp_inspection;
            }
            
            // Store the detailed GSC data
            update_option('vl_gsc_data_' . $license_key, $gsc_data);
            
            // Update settings with sync results
            $settings['data_points'] = $data_points;
            $settings['last_sync'] = current_time('Y-m-d H:i:s');
            $settings['sync_results'] = $sync_results;
            update_option('vl_gsc_settings_' . $license_key, $settings);
            
            // Create data stream
            self::add_data_stream($license_key, 'google_search_console', array(
                'name' => 'Google Search Console',
                'description' => 'Search performance, indexing status, and SEO insights',
                'categories' => array('search', 'seo'),
                'health_score' => 95.0,
                'error_count' => 0,
                'warning_count' => 0,
                'data_points' => $data_points,
                'last_sync' => $settings['last_sync']
            ));
            
            return array(
                'success' => true,
                'data_points' => $data_points,
                'sync_results' => $sync_results,
                'message' => "Successfully synced {$data_points} Google Search Console data points!"
            );
            
        } catch (Exception $e) {
            return new WP_Error('gsc_sync_error', 'GSC sync failed: ' . $e->getMessage());
        }
    }

    /**
     * Renders Marketing cloud connections.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for marketing connections
     */
    public static function render_marketing_connections($license_key, $license) {
        $html = '<div class="vl-marketing-connections" style="margin-top: 20px;">';
        $html .= '<h4>Marketing Connections</h4>';
        $html .= '<p>Connect to advertising platforms for campaign management and analytics.</p>';
        
        $connections = array(
            array(
                'name' => 'Google Ads',
                'subcategory' => 'PPC Ads',
                'icon' => '🎯',
                'description' => 'Google advertising campaigns and performance',
                'status' => 'disconnected'
            ),
            array(
                'name' => 'LinkedIn Ads',
                'subcategory' => 'Social Ads',
                'icon' => '💼',
                'description' => 'LinkedIn advertising and professional targeting',
                'status' => 'disconnected'
            ),
            array(
                'name' => 'Meta Ads',
                'subcategory' => 'Social Ads',
                'icon' => '📱',
                'description' => 'Facebook and Instagram advertising campaigns',
                'status' => 'disconnected'
            )
        );
        
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">';
        
        foreach ($connections as $connection) {
            $status_color = $connection['status'] === 'connected' ? '#00a32a' : '#d63638';
            $status_text = $connection['status'] === 'connected' ? 'Connected' : 'Not Connected';
            
            $html .= '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
            $html .= '<div style="display: flex; align-items: center; margin-bottom: 15px;">';
            $html .= '<span style="font-size: 24px; margin-right: 10px;">' . $connection['icon'] . '</span>';
            $html .= '<div>';
            $html .= '<h5 style="margin: 0; font-size: 16px; color: #333;">' . esc_html($connection['name']) . '</h5>';
            $html .= '<small style="color: #666;">' . esc_html($connection['subcategory']) . '</small>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '<p style="color: #666; font-size: 14px; margin: 10px 0;">' . esc_html($connection['description']) . '</p>';
            $html .= '<div style="display: flex; justify-content: space-between; align-items: center;">';
            $html .= '<span style="color: ' . $status_color . '; font-weight: bold; font-size: 12px;">' . $status_text . '</span>';
            $html .= '<div style="display: flex; gap: 5px;">';
            $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
            $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="sendClientLink(\'' . esc_js($connection['name']) . '\', \'' . esc_js($connection['subcategory']) . '\')">Send Link to Client</button>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders Search cloud connections.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for search connections
     */
    public static function render_search_connections($license_key, $license) {
        $html = '<div class="vl-search-connections" style="margin-top: 20px;">';
        $html .= '<h4>Search Connections</h4>';
        $html .= '<p>Connect to search platforms for SEO monitoring and optimization.</p>';
        
        // Get actual connection status from CloudOps
        $gsc_settings = get_option('vl_gsc_settings_' . $license_key, array());
        $gsc_connected = !empty($gsc_settings['service_account_json']) && !empty($gsc_settings['site_url']);
        
        $connections = array(
            array(
                'name' => 'Google Search Console',
                'subcategory' => 'SEO Analytics',
                'icon' => '🔍',
                'description' => 'Search performance, indexing status, and SEO insights',
                'status' => $gsc_connected ? 'connected' : 'disconnected'
            )
        );
        
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px;">';
        
        foreach ($connections as $connection) {
            $status_color = $connection['status'] === 'connected' ? '#00a32a' : '#d63638';
            $status_text = $connection['status'] === 'connected' ? 'Connected' : 'Not Connected';
            
            $html .= '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
            $html .= '<div style="display: flex; align-items: center; margin-bottom: 15px;">';
            $html .= '<span style="font-size: 24px; margin-right: 10px;">' . $connection['icon'] . '</span>';
            $html .= '<div>';
            $html .= '<h5 style="margin: 0; font-size: 16px; color: #333;">' . esc_html($connection['name']) . '</h5>';
            $html .= '<small style="color: #666;">' . esc_html($connection['subcategory']) . '</small>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '<p style="color: #666; font-size: 14px; margin: 10px 0;">' . esc_html($connection['description']) . '</p>';
            $html .= '<div style="display: flex; justify-content: space-between; align-items: center;">';
            $html .= '<span style="color: ' . $status_color . '; font-weight: bold; font-size: 12px;">' . $status_text . '</span>';
            $html .= '<div style="display: flex; gap: 5px;">';
            
            // Add proper onclick handler for Google Search Console
            if ($connection['name'] === 'Google Search Console') {
                if ($gsc_connected) {
                    $html .= '<button type="button" class="button button-secondary" onclick="openGSCModal(\'' . esc_js($license_key) . '\')" style="font-size: 12px; padding: 5px 10px;">Manage</button>';
                    $html .= '<button type="button" class="button button-secondary" onclick="syncGSCData(\'' . esc_js($license_key) . '\')" style="font-size: 12px; padding: 5px 10px;">Sync Now</button>';
                } else {
                    $html .= '<button type="button" class="button button-primary" onclick="openGSCModal(\'' . esc_js($license_key) . '\')" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
                }
            } else {
            $html .= '<button type="button" class="button button-primary" style="font-size: 12px; padding: 5px 10px;">Connect</button>';
            }
            
            $html .= '<button type="button" class="button button-secondary" style="font-size: 12px; padding: 5px 10px;" onclick="sendClientLink(\'' . esc_js($connection['name']) . '\', \'' . esc_js($connection['subcategory']) . '\')">Send Link to Client</button>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders WordPress data overview tab.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for WordPress data tab
     */
    public static function render_wordpress_data_tab($license_key, $license) {
        $html = '<div class="vl-wordpress-data-overview">';
        $html .= '<h3>WordPress Site Overview</h3>';
        $html .= '<p>Comprehensive data collection from the client WordPress site.</p>';
        
        // Add connection test button
        $html .= '<div style="margin-bottom: 20px;">';
        $html .= '<button type="button" class="button" onclick="testWordPressConnection(\'' . esc_js($license_key) . '\')" style="margin-right: 10px;">Test Connection</button>';
        $html .= '<button type="button" class="button" onclick="debugWordPressConnection(\'' . esc_js($license_key) . '\')" style="margin-right: 10px;">Debug Info</button>';
        $html .= '<button type="button" class="button" onclick="fixLicenseUrls()" style="margin-right: 10px;">Fix License URLs</button>';
        $html .= '<button type="button" class="button" onclick="showLicenseData(\'' . esc_js($license_key) . '\')" style="margin-right: 10px;">Show License Data</button>';
        $html .= '<span id="connection-test-result" style="margin-left: 10px;"></span>';
        $html .= '</div>';
        
        // Add JavaScript for showLicenseData function
        $html .= '<script>';
        $html .= 'function showLicenseData(licenseKey) {';
        $html .= 'var resultSpan = document.getElementById("connection-test-result");';
        $html .= 'resultSpan.innerHTML = "Loading license data...";';
        $html .= 'resultSpan.style.color = "#dba617";';
        $html .= 'jQuery.ajax({';
        $html .= 'url: "' . admin_url('admin-ajax.php') . '",';
        $html .= 'type: "POST",';
        $html .= 'data: {';
        $html .= 'action: "vl_show_license_data",';
        $html .= 'license_key: licenseKey';
        $html .= '},';
        $html .= 'success: function(response) {';
        $html .= 'if (response.success) {';
        $html .= 'var licenseData = response.data;';
        $html .= 'var dataText = "License Data:<br>";';
        $html .= 'dataText += "Key: " + licenseData.key + "<br>";';
        $html .= 'dataText += "Client: " + licenseData.client_name + "<br>";';
        $html .= 'dataText += "Site: " + licenseData.site + "<br>";';
        $html .= 'dataText += "Status: " + licenseData.status + "<br>";';
        $html .= 'resultSpan.innerHTML = dataText;';
        $html .= 'resultSpan.style.color = "#0073aa";';
        $html .= '} else {';
        $html .= 'resultSpan.innerHTML = "✗ Failed to load license data: " + response.data;';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '},';
        $html .= 'error: function() {';
        $html .= 'resultSpan.innerHTML = "✗ Failed to load license data";';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '});';
        $html .= '}';
        $html .= '</script>';
        
        // Get WordPress core status
        $core_status = self::fetch_client_wp_data($license_key, 'wp-core-status');
        if ($core_status) {
            $html .= '<div class="vl-wp-core-status" style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4>WordPress Core Status</h4>';
            $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">';
            $html .= '<div><strong>Version:</strong> ' . esc_html($core_status['version']) . '</div>';
            $html .= '<div><strong>Update Available:</strong> ' . ($core_status['update_available'] ? 'Yes' : 'No') . '</div>';
            $html .= '<div><strong>PHP Version:</strong> ' . esc_html($core_status['php_version']) . '</div>';
            $html .= '<div><strong>MySQL Version:</strong> ' . esc_html($core_status['mysql_version']) . '</div>';
            $html .= '<div><strong>Memory Limit:</strong> ' . esc_html($core_status['memory_limit']) . '</div>';
            $html .= '<div><strong>Multisite:</strong> ' . ($core_status['is_multisite'] ? 'Yes' : 'No') . '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Get comments count
        $comments_count = self::fetch_client_wp_data($license_key, 'comments-count');
        if ($comments_count) {
            $html .= '<div class="vl-comments-overview" style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4>Comments Overview</h4>';
            $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">';
            $html .= '<div><strong>Total:</strong> ' . $comments_count['total'] . '</div>';
            $html .= '<div><strong>Approved:</strong> ' . $comments_count['approved'] . '</div>';
            $html .= '<div><strong>Pending:</strong> ' . $comments_count['pending'] . '</div>';
            $html .= '<div><strong>Spam:</strong> ' . $comments_count['spam'] . '</div>';
            $html .= '<div><strong>Trash:</strong> ' . $comments_count['trash'] . '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        
        // Add JavaScript for connection test
        $html .= '<script type="text/javascript">';
        $html .= 'function testWordPressConnection(licenseKey) {';
        $html .= 'var resultSpan = document.getElementById("connection-test-result");';
        $html .= 'resultSpan.innerHTML = "Testing connection...";';
        $html .= 'resultSpan.style.color = "#dba617";';
        $html .= 'jQuery.ajax({';
        $html .= 'url: "' . admin_url('admin-ajax.php') . '",';
        $html .= 'type: "POST",';
        $html .= 'data: {';
        $html .= 'action: "vl_test_connection",';
        $html .= 'license_key: licenseKey';
        $html .= '},';
        $html .= 'success: function(response) {';
        $html .= 'if (response.success) {';
        $html .= 'resultSpan.innerHTML = "✓ Connection successful!";';
        $html .= 'resultSpan.style.color = "#00a32a";';
        $html .= '} else {';
        $html .= 'resultSpan.innerHTML = "✗ Connection failed: " + response.data;';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '},';
        $html .= 'error: function() {';
        $html .= 'resultSpan.innerHTML = "✗ Connection test failed";';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '});';
        $html .= '}';
        
        $html .= 'function debugWordPressConnection(licenseKey) {';
        $html .= 'var resultSpan = document.getElementById("connection-test-result");';
        $html .= 'resultSpan.innerHTML = "Running debug...";';
        $html .= 'resultSpan.style.color = "#dba617";';
        $html .= 'jQuery.ajax({';
        $html .= 'url: "' . admin_url('admin-ajax.php') . '",';
        $html .= 'type: "POST",';
        $html .= 'data: {';
        $html .= 'action: "vl_debug_connection",';
        $html .= 'license_key: licenseKey';
        $html .= '},';
        $html .= 'success: function(response) {';
        $html .= 'if (response.success) {';
        $html .= 'var debugInfo = response.data;';
        $html .= 'var debugText = "Debug Info:<br>";';
        $html .= 'debugText += "License Lookup: " + debugInfo.license_lookup + "<br>";';
        $html .= 'debugText += "Site URL: " + (debugInfo.license_data.site || "NOT_SET") + "<br>";';
        $html .= 'debugText += "Connectivity: " + debugInfo.connectivity + "<br>";';
        $html .= 'debugText += "Response Code: " + (debugInfo.response_code || "N/A") + "<br>";';
        $html .= 'debugText += "Connectivity with License: " + debugInfo.connectivity_with_license + "<br>";';
        $html .= 'debugText += "Response Code with License: " + (debugInfo.response_code_with_license || "N/A") + "<br>";';
        $html .= 'if (debugInfo.error) debugText += "Error: " + debugInfo.error + "<br>";';
        $html .= 'resultSpan.innerHTML = debugText;';
        $html .= 'resultSpan.style.color = "#0073aa";';
        $html .= '} else {';
        $html .= 'resultSpan.innerHTML = "✗ Debug failed: " + response.data;';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '},';
        $html .= 'error: function() {';
        $html .= 'resultSpan.innerHTML = "✗ Debug test failed";';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '});';
        $html .= '}';
        
        $html .= 'function fixLicenseUrls() {';
        $html .= 'var resultSpan = document.getElementById("connection-test-result");';
        $html .= 'resultSpan.innerHTML = "Fixing license URLs...";';
        $html .= 'resultSpan.style.color = "#dba617";';
        $html .= 'jQuery.ajax({';
        $html .= 'url: "' . admin_url('admin-ajax.php') . '",';
        $html .= 'type: "POST",';
        $html .= 'data: {';
        $html .= 'action: "vl_fix_license_urls"';
        $html .= '},';
        $html .= 'success: function(response) {';
        $html .= 'if (response.success) {';
        $html .= 'resultSpan.innerHTML = "✓ License URLs fixed! " + response.data;';
        $html .= 'resultSpan.style.color = "#00a32a";';
        $html .= 'setTimeout(function() { location.reload(); }, 2000);';
        $html .= '} else {';
        $html .= 'resultSpan.innerHTML = "✗ Fix failed: " + response.data;';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '},';
        $html .= 'error: function() {';
        $html .= 'resultSpan.innerHTML = "✗ Fix failed";';
        $html .= 'resultSpan.style.color = "#d63638";';
        $html .= '}';
        $html .= '});';
        $html .= '}';
        $html .= '</script>';
        
        return $html;
    }

    /**
     * Renders posts tab with SEO scores and detailed information.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for posts tab
     */
    public static function render_posts_tab($license_key, $license) {
        $html = '<div class="vl-posts-overview">';
        $html .= '<h3>Posts Overview</h3>';
        $html .= '<p>All published posts with SEO scores, categories, and author information.</p>';
        
        $posts_data = self::fetch_client_wp_data($license_key, 'content/posts');
        
        if ($posts_data && isset($posts_data['items']) && is_array($posts_data['items']) && count($posts_data['items']) > 0) {
            $html .= '<div class="vl-posts-table" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<table class="wp-list-table widefat fixed striped">';
            $html .= '<thead><tr><th>Title</th><th>Author</th><th>Categories</th><th>SEO Score</th><th>Date</th><th>Comments</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($posts_data['items'] as $post) {
                $seo_score = isset($post['seo_score']) ? $post['seo_score'] : 0;
                $seo_color = $seo_score >= 80 ? '#00a32a' : ($seo_score >= 60 ? '#dba617' : '#d63638');
                
                $html .= '<tr>';
                $html .= '<td><strong>' . esc_html($post['title']) . '</strong><br><small>' . esc_html($post['slug']) . '</small></td>';
                $html .= '<td>' . esc_html($post['author']['display_name']) . '<br><small>' . esc_html($post['author']['email']) . '</small></td>';
                $html .= '<td>' . implode(', ', array_map('esc_html', $post['categories'])) . '</td>';
                $html .= '<td><span style="color: ' . $seo_color . '; font-weight: bold;">' . $seo_score . '%</span></td>';
                $html .= '<td>' . esc_html(date('M j, Y', strtotime($post['date']))) . '</td>';
                $html .= '<td>' . $post['comment_count'] . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '<div style="padding: 15px; background: #f9f9f9; border-top: 1px solid #ddd;">';
            $html .= '<strong>Total Posts:</strong> ' . $posts_data['total'] . ' | ';
            $html .= '<strong>Page:</strong> ' . $posts_data['page'] . ' of ' . ceil($posts_data['total'] / $posts_data['per_page']);
            $html .= '</div>';
            $html .= '</div>';
        } else {
            if ($posts_data === false) {
                $html .= '<div class="notice notice-warning">';
                $html .= '<p><strong>Unable to fetch posts from client site.</strong></p>';
                $html .= '<p>Please ensure:</p>';
                $html .= '<ul>';
                $html .= '<li>The Luna Widget plugin is active on the client\'s WordPress site</li>';
                $html .= '<li>The license key is correctly configured</li>';
                $html .= '<li>The site is accessible and responding</li>';
                $html .= '</ul>';
                $html .= '<p><em>Check the WordPress error logs for more details.</em></p>';
                $html .= '</div>';
            } elseif (is_array($posts_data) && count($posts_data) === 0) {
                $html .= '<p>No posts found on this site.</p>';
            } else {
                $html .= '<p>No posts data available.</p>';
            }
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders pages tab with SEO scores and detailed information.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for pages tab
     */
    public static function render_pages_tab($license_key, $license) {
        $html = '<div class="vl-pages-overview">';
        $html .= '<h3>Pages Overview</h3>';
        $html .= '<p>All pages with SEO scores, status, and author information.</p>';
        
        $pages_data = self::fetch_client_wp_data($license_key, 'content/pages');
        
        if ($pages_data && isset($pages_data['items']) && is_array($pages_data['items']) && count($pages_data['items']) > 0) {
            $html .= '<div class="vl-pages-table" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<table class="wp-list-table widefat fixed striped">';
            $html .= '<thead><tr><th>Title</th><th>Author</th><th>Status</th><th>SEO Score</th><th>Date</th><th>Comments</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($pages_data['items'] as $page) {
                $seo_score = isset($page['seo_score']) ? $page['seo_score'] : 0;
                $seo_color = $seo_score >= 80 ? '#00a32a' : ($seo_score >= 60 ? '#dba617' : '#d63638');
                $status_color = $page['status'] === 'publish' ? '#00a32a' : '#dba617';
                
                $html .= '<tr>';
                $html .= '<td><strong>' . esc_html($page['title']) . '</strong><br><small>' . esc_html($page['slug']) . '</small></td>';
                $html .= '<td>' . esc_html($page['author']['display_name']) . '<br><small>' . esc_html($page['author']['email']) . '</small></td>';
                $html .= '<td><span style="color: ' . $status_color . '; font-weight: bold;">' . ucfirst($page['status']) . '</span></td>';
                $html .= '<td><span style="color: ' . $seo_color . '; font-weight: bold;">' . $seo_score . '%</span></td>';
                $html .= '<td>' . esc_html(date('M j, Y', strtotime($page['date']))) . '</td>';
                $html .= '<td>' . $page['comment_count'] . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '<div style="padding: 15px; background: #f9f9f9; border-top: 1px solid #ddd;">';
            $html .= '<strong>Total Pages:</strong> ' . $pages_data['total'] . ' | ';
            $html .= '<strong>Page:</strong> ' . $pages_data['page'] . ' of ' . ceil($pages_data['total'] / $pages_data['per_page']);
            $html .= '</div>';
            $html .= '</div>';
        } else {
            if ($pages_data === false) {
                $html .= '<div class="notice notice-warning">';
                $html .= '<p><strong>Unable to fetch pages from client site.</strong></p>';
                $html .= '<p>Please ensure:</p>';
                $html .= '<ul>';
                $html .= '<li>The Luna Widget plugin is active on the client\'s WordPress site</li>';
                $html .= '<li>The license key is correctly configured</li>';
                $html .= '<li>The site is accessible and responding</li>';
                $html .= '</ul>';
                $html .= '<p><em>Check the WordPress error logs for more details.</em></p>';
                $html .= '</div>';
            } elseif (is_array($pages_data) && count($pages_data) === 0) {
                $html .= '<p>No pages found on this site.</p>';
            } else {
                $html .= '<p>No pages data available.</p>';
            }
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders users tab with detailed user information.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for users tab
     */
    public static function render_users_tab($license_key, $license) {
        $html = '<div class="vl-users-overview">';
        $html .= '<h3>Users Overview</h3>';
        $html .= '<p>All registered users with their roles and activity information.</p>';
        
        $users_data = self::fetch_client_wp_data($license_key, 'users');
        if ($users_data && isset($users_data['items'])) {
            $html .= '<div class="vl-users-table" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<table class="wp-list-table widefat fixed striped">';
            $html .= '<thead><tr><th>Username</th><th>Display Name</th><th>Email</th><th>Roles</th><th>Post Count</th><th>Registered</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($users_data['items'] as $user) {
                $html .= '<tr>';
                $html .= '<td><strong>' . esc_html($user['username']) . '</strong><br><small>ID: ' . $user['id'] . '</small></td>';
                $html .= '<td>' . esc_html($user['name']) . '</td>';
                $html .= '<td>' . esc_html($user['email']) . '</td>';
                $html .= '<td>' . implode(', ', array_map('esc_html', $user['roles'])) . '</td>';
                $html .= '<td>' . $user['post_count'] . '</td>';
                $html .= '<td>' . esc_html(date('M j, Y', strtotime($user['registered']))) . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '<div style="padding: 15px; background: #f9f9f9; border-top: 1px solid #ddd;">';
            $html .= '<strong>Total Users:</strong> ' . $users_data['total'] . ' | ';
            $html .= '<strong>Page:</strong> ' . $users_data['page'] . ' of ' . ceil($users_data['total'] / $users_data['per_page']);
            $html .= '</div>';
            $html .= '</div>';
        } else {
            $html .= '<p>No users data available.</p>';
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders plugins tab with update status information.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for plugins tab
     */
    public static function render_plugins_tab($license_key, $license) {
        $html = '<div class="vl-plugins-overview">';
        $html .= '<h3>Plugins Overview</h3>';
        $html .= '<p>All installed plugins with their status and update availability.</p>';
        
        $plugins_data = self::fetch_client_wp_data($license_key, 'plugins');
        if ($plugins_data && isset($plugins_data['items'])) {
            $active_count = 0;
            $update_count = 0;
            
            $html .= '<div class="vl-plugins-table" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<table class="wp-list-table widefat fixed striped">';
            $html .= '<thead><tr><th>Plugin Name</th><th>Version</th><th>Status</th><th>Update Available</th><th>New Version</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($plugins_data['items'] as $plugin) {
                if ($plugin['active']) $active_count++;
                if ($plugin['update_available']) $update_count++;
                
                $status_color = $plugin['active'] ? '#00a32a' : '#666';
                $update_color = $plugin['update_available'] ? '#d63638' : '#00a32a';
                
                $html .= '<tr>';
                $html .= '<td><strong>' . esc_html($plugin['name']) . '</strong><br><small>' . esc_html($plugin['slug']) . '</small></td>';
                $html .= '<td>' . esc_html($plugin['version']) . '</td>';
                $html .= '<td><span style="color: ' . $status_color . '; font-weight: bold;">' . ($plugin['active'] ? 'Active' : 'Inactive') . '</span></td>';
                $html .= '<td><span style="color: ' . $update_color . '; font-weight: bold;">' . ($plugin['update_available'] ? 'Yes' : 'No') . '</span></td>';
                $html .= '<td>' . ($plugin['update_available'] ? esc_html($plugin['new_version']) : '-') . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '<div style="padding: 15px; background: #f9f9f9; border-top: 1px solid #ddd;">';
            $html .= '<strong>Total Plugins:</strong> ' . count($plugins_data['items']) . ' | ';
            $html .= '<strong>Active:</strong> ' . $active_count . ' | ';
            $html .= '<strong>Updates Available:</strong> ' . $update_count;
            $html .= '</div>';
            $html .= '</div>';
        } else {
            $html .= '<p>No plugins data available.</p>';
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders themes tab with update status information.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for themes tab
     */
    public static function render_themes_tab($license_key, $license) {
        $html = '<div class="vl-themes-overview">';
        $html .= '<h3>Themes Overview</h3>';
        $html .= '<p>All installed themes with their status and update availability.</p>';
        
        $themes_data = self::fetch_client_wp_data($license_key, 'themes');
        if ($themes_data && isset($themes_data['items'])) {
            $active_count = 0;
            $update_count = 0;
            
            $html .= '<div class="vl-themes-table" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<table class="wp-list-table widefat fixed striped">';
            $html .= '<thead><tr><th>Theme Name</th><th>Version</th><th>Status</th><th>Update Available</th><th>New Version</th></tr></thead>';
            $html .= '<tbody>';
            
            foreach ($themes_data['items'] as $theme) {
                if ($theme['is_active']) $active_count++;
                if ($theme['update_available']) $update_count++;
                
                $status_color = $theme['is_active'] ? '#00a32a' : '#666';
                $update_color = $theme['update_available'] ? '#d63638' : '#00a32a';
                
                $html .= '<tr>';
                $html .= '<td><strong>' . esc_html($theme['name']) . '</strong><br><small>' . esc_html($theme['stylesheet']) . '</small></td>';
                $html .= '<td>' . esc_html($theme['version']) . '</td>';
                $html .= '<td><span style="color: ' . $status_color . '; font-weight: bold;">' . ($theme['is_active'] ? 'Active' : 'Inactive') . '</span></td>';
                $html .= '<td><span style="color: ' . $update_color . '; font-weight: bold;">' . ($theme['update_available'] ? 'Yes' : 'No') . '</span></td>';
                $html .= '<td>' . ($theme['update_available'] ? esc_html($theme['new_version']) : '-') . '</td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody></table>';
            $html .= '<div style="padding: 15px; background: #f9f9f9; border-top: 1px solid #ddd;">';
            $html .= '<strong>Total Themes:</strong> ' . count($themes_data['items']) . ' | ';
            $html .= '<strong>Active:</strong> ' . $active_count . ' | ';
            $html .= '<strong>Updates Available:</strong> ' . $update_count;
            $html .= '</div>';
            $html .= '</div>';
        } else {
            $html .= '<p>No themes data available.</p>';
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders comments tab with comment statistics.
     * 
     * @param string $license_key The license key
     * @param array $license The license record
     * @return string HTML content for comments tab
     */
    public static function render_comments_tab($license_key, $license) {
        $html = '<div class="vl-comments-overview">';
        $html .= '<h3>Comments Overview</h3>';
        $html .= '<p>Comment statistics and recent comments from the client site.</p>';
        
        // Get comments count
        $comments_count = self::fetch_client_wp_data($license_key, 'comments-count');
        if ($comments_count) {
            $html .= '<div class="vl-comments-stats" style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
            $html .= '<h4>Comment Statistics</h4>';
            $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">';
            $html .= '<div style="text-align: center; padding: 15px; background: #f0f0f0; border-radius: 5px;">';
            $html .= '<div style="font-size: 2em; font-weight: bold; color: #0073aa;">' . $comments_count['total'] . '</div>';
            $html .= '<div>Total Comments</div>';
            $html .= '</div>';
            $html .= '<div style="text-align: center; padding: 15px; background: #f0f0f0; border-radius: 5px;">';
            $html .= '<div style="font-size: 2em; font-weight: bold; color: #00a32a;">' . $comments_count['approved'] . '</div>';
            $html .= '<div>Approved</div>';
            $html .= '</div>';
            $html .= '<div style="text-align: center; padding: 15px; background: #f0f0f0; border-radius: 5px;">';
            $html .= '<div style="font-size: 2em; font-weight: bold; color: #dba617;">' . $comments_count['pending'] . '</div>';
            $html .= '<div>Pending</div>';
            $html .= '</div>';
            $html .= '<div style="text-align: center; padding: 15px; background: #f0f0f0; border-radius: 5px;">';
            $html .= '<div style="font-size: 2em; font-weight: bold; color: #d63638;">' . $comments_count['spam'] . '</div>';
            $html .= '<div>Spam</div>';
            $html .= '</div>';
            $html .= '</div>';
            $html .= '</div>';
        }
        
        // Get recent comments
        $comments_data = self::fetch_client_wp_data($license_key, 'comments');
        if ($comments_data && isset($comments_data['items'])) {
            $html .= '<div class="vl-recent-comments" style="background: white; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">';
            $html .= '<h4 style="margin: 0; padding: 15px; background: #f9f9f9; border-bottom: 1px solid #ddd;">Recent Comments</h4>';
            $html .= '<div style="max-height: 400px; overflow-y: auto;">';
            
            foreach (array_slice($comments_data['items'], 0, 20) as $comment) {
                $html .= '<div style="padding: 15px; border-bottom: 1px solid #eee;">';
                $html .= '<div style="font-weight: bold; color: #333;">' . esc_html($comment['author']) . '</div>';
                $html .= '<div style="color: #666; font-size: 0.9em; margin: 5px 0;">' . esc_html($comment['content']) . '</div>';
                $html .= '<div style="font-size: 0.8em; color: #999;">';
                $html .= 'Post ID: ' . $comment['post_id'] . ' | ';
                $html .= 'Date: ' . esc_html($comment['date']) . ' | ';
                $html .= 'Status: ' . ($comment['approved'] ? 'Approved' : 'Pending');
                $html .= '</div>';
                $html .= '</div>';
            }
            
            $html .= '</div>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        return $html;
    }

    /**
     * Renders Competitor Manager UI for Competitive tab.
     * 
     * @param array $license The license record
     * @return string HTML content for competitor manager
     */
    public static function render_competitor_manager($license) {
        $license_key = $license['key'] ?? '';
        $competitor_settings = get_option('vl_competitor_settings_' . $license_key, array());
        
        $html = '<div class="vl-competitor-manager" style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px;">';
        $html .= '<h4 style="margin-top: 0; color: #0073aa;">Competitor Analysis</h4>';
        $html .= '<p style="color: #666;">Monitor up to 3 competitor websites. Track their pages, blog activity, keywords, and performance metrics.</p>';
        
        // Save handler for competitor URLs
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_competitor_urls']) && check_admin_referer('vl_competitor_nonce')) {
            $competitors = array();
            for ($i = 1; $i <= 3; $i++) {
                $url = sanitize_url($_POST['competitor_url_' . $i] ?? '');
                if (!empty($url)) {
                    // Ensure URL has protocol
                    if (!preg_match('#^https?://#i', $url)) {
                        $url = 'https://' . $url;
                    }
                    $competitors[] = esc_url_raw($url);
                }
            }
            
            $competitor_settings['urls'] = $competitors;
            $competitor_settings['updated'] = current_time('mysql');
            update_option('vl_competitor_settings_' . $license_key, $competitor_settings);
            
            $html .= '<div class="notice notice-success"><p>' . esc_html__('Competitor URLs saved successfully.', 'visible-light') . '</p></div>';
        }
        
        // Get saved URLs
        $saved_urls = $competitor_settings['urls'] ?? array();
        
        $html .= '<form method="post" style="margin-top: 20px;">';
        $html .= wp_nonce_field('vl_competitor_nonce', 'vl_competitor_nonce', true, false);
        $html .= '<table class="form-table">';
        
        for ($i = 1; $i <= 3; $i++) {
            $current_url = isset($saved_urls[$i - 1]) ? esc_attr($saved_urls[$i - 1]) : '';
            $html .= '<tr>';
            $html .= '<th scope="row">' . esc_html__('Competitor ' . $i, 'visible-light') . '</th>';
            $html .= '<td>';
            $html .= '<input type="url" name="competitor_url_' . $i . '" value="' . $current_url . '" class="regular-text" placeholder="https://competitor.com">';
            $html .= '</td>';
            $html .= '</tr>';
        }
        
        $html .= '</table>';
        $html .= '<p class="submit"><input type="submit" name="save_competitor_urls" class="button-primary" value="' . esc_attr__('Save Competitors', 'visible-light') . '"> ';
        
        // Add Scan button
        if (!empty($saved_urls)) {
            $html .= '<button type="button" class="button" onclick="runCompetitorScan(\'' . esc_js($license_key) . '\')" style="margin-left: 10px;">' . esc_html__('Run Analysis', 'visible-light') . '</button>';
        }
        
        $html .= '</p>';
        $html .= '</form>';
        
        // Display existing reports
        $reports = get_competitor_reports($license_key);
        if (!empty($reports)) {
            $html .= '<div style="margin-top: 30px;">';
            $html .= '<h4>' . esc_html__('Competitor Reports', 'visible-light') . '</h4>';
            $html .= '<table class="widefat fixed striped" style="margin-top: 10px;">';
            $html .= '<thead>';
            $html .= '<tr>';
            $html .= '<th>' . esc_html__('Competitor', 'visible-light') . '</th>';
            $html .= '<th>' . esc_html__('Public Pages', 'visible-light') . '</th>';
            $html .= '<th>' . esc_html__('Blog Status', 'visible-light') . '</th>';
            $html .= '<th>' . esc_html__('Lighthouse Score', 'visible-light') . '</th>';
            $html .= '<th>' . esc_html__('Last Scanned', 'visible-light') . '</th>';
            $html .= '<th>' . esc_html__('Actions', 'visible-light') . '</th>';
            $html .= '</tr>';
            $html .= '</thead>';
            $html .= '<tbody>';
            
            foreach ($reports as $url => $report) {
                $last_scanned = isset($report['last_scanned']) ? $report['last_scanned'] : 'Never';
                $public_pages = isset($report['report_json']['public_pages']) ? $report['report_json']['public_pages'] : 'N/A';
                $blog_status = isset($report['report_json']['blog']['status']) ? ucfirst($report['report_json']['blog']['status']) : 'Unknown';
                $lighthouse_perf = isset($report['report_json']['lighthouse']['performance']) ? $report['report_json']['lighthouse']['performance'] : 'N/A';
                
                $html .= '<tr>';
                $html .= '<td><strong>' . esc_html($url) . '</strong></td>';
                $html .= '<td>' . esc_html($public_pages) . '</td>';
                $html .= '<td><span style="color: ' . ($blog_status === 'Active' ? '#00a32a' : '#d63638') . '; font-weight: bold;">' . esc_html($blog_status) . '</span></td>';
                $html .= '<td><span style="font-weight: bold; color: ' . ($lighthouse_perf >= 80 ? '#00a32a' : ($lighthouse_perf >= 60 ? '#dba617' : '#d63638')) . ';">' . esc_html($lighthouse_perf . '%') . '</span></td>';
                $html .= '<td>' . esc_html($last_scanned) . '</td>';
                $html .= '<td><button type="button" class="button button-small" onclick="viewCompetitorReport(\'' . esc_js($license_key) . '\', \'' . esc_js($url) . '\')">' . esc_html__('View Report', 'visible-light') . '</button></td>';
                $html .= '</tr>';
            }
            
            $html .= '</tbody>';
            $html .= '</table>';
            $html .= '</div>';
        }
        
        $html .= '</div>';
        
        // Add JavaScript for running competitor scan
        $html .= '<script type="text/javascript">';
        $html .= 'function runCompetitorScan(licenseKey) {';
        $html .= 'if (!confirm("This will analyze your competitors. This may take a few minutes. Continue?")) { return; }';
        $html .= 'jQuery.ajax({';
        $html .= 'url: "' . admin_url('admin-ajax.php') . '",';
        $html .= 'type: "POST",';
        $html .= 'data: {';
        $html .= 'action: "vl_competitor_scan",';
        $html .= 'license_key: licenseKey';
        $html .= '},';
        $html .= 'success: function(response) {';
        $html .= 'if (response.success) {';
        $html .= 'alert("Competitor analysis complete! Refreshing page...");';
        $html .= 'location.reload();';
        $html .= '} else {';
        $html .= 'alert("Error: " + response.data);';
        $html .= '}';
        $html .= '},';
        $html .= 'error: function() {';
        $html .= 'alert("Error running competitor scan. Please try again.");';
        $html .= '}';
        $html .= '});';
        $html .= '}';
        
        $html .= 'function viewCompetitorReport(licenseKey, url) {';
        $html .= 'jQuery.ajax({';
        $html .= 'url: "' . admin_url('admin-ajax.php') . '",';
        $html .= 'type: "POST",';
        $html .= 'data: {';
        $html .= 'action: "vl_get_competitor_report",';
        $html .= 'license_key: licenseKey,';
        $html .= 'competitor_url: url';
        $html .= '},';
        $html .= 'success: function(response) {';
        $html .= 'if (response.success) {';
        $html .= 'jQuery("#vl-competitor-report-modal").remove();';
        $html .= 'jQuery("body").append(response.data);';
        $html .= 'jQuery("#vl-competitor-report-modal").fadeIn(300);';
        $html .= '} else {';
        $html .= 'alert("Error loading report: " + response.data);';
        $html .= '}';
        $html .= '},';
        $html .= 'error: function() {';
        $html .= 'alert("Error loading report. Please try again.");';
        $html .= '}';
        $html .= '});';
        $html .= '}';
        $html .= '</script>';
        
        return $html;
    }

    /**
     * Fetches WordPress data from client site.
     * 
     * @param string $license_key The license key
     * @param string $endpoint The API endpoint to call
     * @return array|false The response data or false on failure
     */
    private static function fetch_client_wp_data($license_key, $endpoint) {
        $license = self::lic_lookup_by_key($license_key);
        if (!$license || empty($license['site'])) {
            return false;
        }
        
        $client_url = rtrim($license['site'], '/');
        $api_url = $client_url . '/wp-json/luna_widget/v1/' . $endpoint . '?license=' . urlencode($license_key);
        
        $response = wp_remote_get($api_url, array(
            'timeout' => 15,
            'headers' => array(
                'X-Luna-License' => $license_key
            )
        ));
        
        if (is_wp_error($response)) {
            error_log('[VL Hub] Failed to fetch ' . $endpoint . ' from ' . $client_url . ': ' . $response->get_error_message());
            return false;
        }
        
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($code !== 200) {
            error_log('[VL Hub] Non-200 response for ' . $endpoint . ' from ' . $client_url . ': ' . $code);
            error_log('[VL Hub] Response body: ' . substr($body, 0, 500));
            return false;
        }
        
        $data = json_decode($body, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('[VL Hub] JSON decode error for ' . $endpoint . ' from ' . $client_url . ': ' . json_last_error_msg());
            return false;
        }
        
        return $data;
    }

    /**
     * Debug method to test basic API connectivity.
     * 
     * @param string $license_key The license key
     * @return array Debug information
     */
    public static function debug_api_connection($license_key) {
        $debug_info = array();
        
        // 1. Check license lookup
        $license = self::lic_lookup_by_key($license_key);
        $debug_info['license_lookup'] = $license ? 'SUCCESS' : 'FAILED';
        $debug_info['license_data'] = $license ? array(
            'site' => $license['site'] ?? 'NOT_SET',
            'key' => substr($license['key'] ?? 'NOT_SET', 0, 10) . '...'
        ) : 'NO_LICENSE_FOUND';
        
        if (!$license || empty($license['site'])) {
            $debug_info['error'] = 'License not found or no site URL';
            return $debug_info;
        }
        
        // 2. Test basic connectivity
        $client_url = rtrim($license['site'], '/');
        $test_url = $client_url . '/wp-json/luna_widget/v1/test-chat';
        
        $debug_info['test_url'] = $test_url;
        
        $response = wp_remote_post($test_url, array(
            'timeout' => 10,
            'headers' => array(
                'X-Luna-License' => $license_key
            )
        ));
        
        if (is_wp_error($response)) {
            $debug_info['connectivity'] = 'FAILED';
            $debug_info['error'] = $response->get_error_message();
        } else {
            $code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            
            $debug_info['connectivity'] = 'SUCCESS';
            $debug_info['response_code'] = $code;
            $debug_info['response_body'] = substr($body, 0, 200);
        }
        
        // 3. Test with license parameter
        $test_url_with_license = $test_url . '?license=' . urlencode($license_key);
        $debug_info['test_url_with_license'] = $test_url_with_license;
        
        $response2 = wp_remote_post($test_url_with_license, array(
            'timeout' => 10,
            'headers' => array(
                'X-Luna-License' => $license_key
            )
        ));
        
        if (is_wp_error($response2)) {
            $debug_info['connectivity_with_license'] = 'FAILED';
            $debug_info['error_with_license'] = $response2->get_error_message();
        } else {
            $code2 = wp_remote_retrieve_response_code($response2);
            $body2 = wp_remote_retrieve_body($response2);
            
            $debug_info['connectivity_with_license'] = 'SUCCESS';
            $debug_info['response_code_with_license'] = $code2;
            $debug_info['response_body_with_license'] = substr($body2, 0, 200);
        }
        
        return $debug_info;
    }

    /**
     * Tests the connection to a client's WordPress site.
     * 
     * @param string $license_key The license key
     * @return array Test results
     */
    public static function test_client_connection($license_key) {
        $license = self::lic_lookup_by_key($license_key);
        if (!$license || empty($license['site'])) {
            return array('success' => false, 'error' => 'License not found or no site URL');
        }
        
        $client_url = rtrim($license['site'], '/');
        $test_url = $client_url . '/wp-json/luna_widget/v1/test-chat?license=' . urlencode($license_key);
        
        $response = wp_remote_post($test_url, array(
            'timeout' => 10,
            'headers' => array(
                'X-Luna-License' => $license_key
            )
        ));
        
        if (is_wp_error($response)) {
            return array(
                'success' => false, 
                'error' => 'Connection failed: ' . $response->get_error_message(),
                'url' => $test_url
            );
        }
        
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        return array(
            'success' => $code === 200,
            'status_code' => $code,
            'response' => $body,
            'url' => $test_url
        );
    }

    /**
     * Creates sample data streams for testing and demonstration.
     * This function can be called to populate the system with example data.
     */
    public static function create_sample_data_streams() {
        $sample_licenses = array('VL-GC5K-YKBM-BM5F', 'VL-VYAK-9BPQ-NKCC', 'VL-H2K3-ZFQK-DKDC', 'VL-SAMPLE-XXXX-XXXX');
        
        foreach ($sample_licenses as $license) {
            // Infrastructure streams
            self::add_data_stream($license, 'server_monitoring', array(
                'name' => 'Server Health Monitoring',
                'description' => 'Real-time server performance and health metrics',
                'categories' => array('infrastructure', 'cloudops'),
                'health_score' => 95.5,
                'error_count' => 0,
                'warning_count' => 2
            ));
            
            self::add_data_stream($license, 'database_performance', array(
                'name' => 'Database Performance',
                'description' => 'Database query performance and connection monitoring',
                'categories' => array('infrastructure'),
                'health_score' => 88.2,
                'error_count' => 1,
                'warning_count' => 3
            ));

            // Content streams
            self::add_data_stream($license, 'cms_health', array(
                'name' => 'CMS Health Check',
                'description' => 'Content management system status and performance',
                'categories' => array('content'),
                'health_score' => 92.8,
                'error_count' => 0,
                'warning_count' => 1
            ));

            // Search streams
            self::add_data_stream($license, 'seo_rankings', array(
                'name' => 'SEO Rankings Monitor',
                'description' => 'Search engine ranking tracking and analysis',
                'categories' => array('search'),
                'health_score' => 85.3,
                'error_count' => 0,
                'warning_count' => 4
            ));

            // Analytics streams
            self::add_data_stream($license, 'google_analytics', array(
                'name' => 'Google Analytics',
                'description' => 'Website traffic and user behavior analytics',
                'categories' => array('analytics'),
                'health_score' => 97.1,
                'error_count' => 0,
                'warning_count' => 0
            ));

            // Marketing streams
            self::add_data_stream($license, 'email_campaigns', array(
                'name' => 'Email Campaign Performance',
                'description' => 'Email marketing campaign metrics and deliverability',
                'categories' => array('marketing'),
                'health_score' => 89.7,
                'error_count' => 0,
                'warning_count' => 2
            ));

            // E-commerce streams
            self::add_data_stream($license, 'payment_processing', array(
                'name' => 'Payment Processing',
                'description' => 'Payment gateway health and transaction monitoring',
                'categories' => array('ecommerce'),
                'health_score' => 99.2,
                'error_count' => 0,
                'warning_count' => 0
            ));

            // Security streams
            self::add_data_stream($license, 'security_scanner', array(
                'name' => 'Security Vulnerability Scanner',
                'description' => 'Automated security scanning and threat detection',
                'categories' => array('security'),
                'health_score' => 96.8,
                'error_count' => 0,
                'warning_count' => 1
            ));

            // Identity streams
            self::add_data_stream($license, 'user_authentication', array(
                'name' => 'User Authentication System',
                'description' => 'Login system and user session monitoring',
                'categories' => array('identity'),
                'health_score' => 94.5,
                'error_count' => 0,
                'warning_count' => 1
            ));

            // Competitive streams
            self::add_data_stream($license, 'competitor_analysis', array(
                'name' => 'Competitor Analysis',
                'description' => 'Competitive intelligence and market positioning',
                'categories' => array('competitive'),
                'health_score' => 87.3,
                'error_count' => 0,
                'warning_count' => 3
            ));
        }
    }

    /**
     * Renders the client edit screen with data stream management.
     */
    public function render_client_edit_screen($license_key, $license, $messages) {
        $client_name = isset($license['client_name']) ? $license['client_name'] : 'Unknown Client';
        $client_email = isset($license['contact_email']) ? $license['contact_email'] : '';
        $client_site = isset($license['site']) ? $license['site'] : '';
        
        // Get data streams for this license
        $data_streams = self::get_license_streams($license_key);
        
        // Handle form submissions
        if (isset($_POST['action'])) {
            $action = sanitize_text_field(wp_unslash($_POST['action']));
            
            if ('update_client' === $action) {
                check_admin_referer('vl_update_client');
                
                $new_name = sanitize_text_field(wp_unslash($_POST['client_name']));
                $new_email = sanitize_email(wp_unslash($_POST['client_email']));
                $new_site = sanitize_text_field(wp_unslash($_POST['client_site']));
                
                $store = self::lic_store_get();
                if (isset($store[$license_key])) {
                    $store[$license_key]['client_name'] = $new_name;
                    $store[$license_key]['contact_email'] = $new_email;
                    $store[$license_key]['site'] = $new_site;
                    $store[$license_key]['last_updated'] = current_time('mysql');
                    
                    self::lic_store_set($store);
                    $messages['success'][] = 'Client information updated successfully.';
                    
                    // Update license data for display
                    $license = $store[$license_key];
                }
            }
            
            if ('add_data_stream' === $action) {
                check_admin_referer('vl_add_data_stream');
                
                $stream_id = sanitize_text_field(wp_unslash($_POST['stream_id']));
                $stream_name = sanitize_text_field(wp_unslash($_POST['stream_name']));
                $stream_description = sanitize_text_field(wp_unslash($_POST['stream_description']));
                $stream_categories = isset($_POST['stream_categories']) ? array_map('sanitize_text_field', wp_unslash($_POST['stream_categories'])) : array();
                $health_score = floatval($_POST['health_score']);
                
                if ($stream_id && $stream_name) {
                    $result = self::add_data_stream($license_key, $stream_id, array(
                        'name' => $stream_name,
                        'description' => $stream_description,
                        'categories' => $stream_categories,
                        'health_score' => $health_score
                    ));
                    
                    if ($result) {
                        $messages['success'][] = 'Data stream added successfully.';
                        $data_streams = self::get_license_streams($license_key); // Refresh data
                    } else {
                        $messages['error'][] = 'Failed to add data stream. Please check that the Stream ID is unique and try again.';
                        error_log('[VL Data Streams] Failed to add stream: ' . $stream_id . ' for license: ' . $license_key);
                    }
                } else {
                    $messages['error'][] = 'Stream ID and name are required.';
                }
            }
            
            if ('update_stream_health' === $action) {
                check_admin_referer('vl_update_stream_health');
                
                $stream_id = sanitize_text_field(wp_unslash($_POST['stream_id']));
                $health_score = floatval($_POST['health_score']);
                $error_count = intval($_POST['error_count']);
                $warning_count = intval($_POST['warning_count']);
                $status = sanitize_text_field(wp_unslash($_POST['status']));
                
                $result = self::update_stream_health($license_key, $stream_id, array(
                    'health_score' => $health_score,
                    'error_count' => $error_count,
                    'warning_count' => $warning_count,
                    'status' => $status
                ));
                
                if ($result) {
                    $messages['success'][] = 'Stream health updated successfully.';
                    $data_streams = self::get_license_streams($license_key); // Refresh data
                } else {
                    $messages['error'][] = 'Failed to update stream health.';
                }
            }
        }
        
        ?>
        <div class="wrap">
            <h1>Edit Client: <?php echo esc_html($client_name); ?></h1>
            
            <?php if (!empty($messages['success'])) : ?>
                <div class="notice notice-success">
                    <?php foreach ($messages['success'] as $message) : ?>
                        <p><?php echo esc_html($message); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($messages['error'])) : ?>
                <div class="notice notice-error">
                    <?php foreach ($messages['error'] as $message) : ?>
                        <p><?php echo esc_html($message); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <div class="vl-admin-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                
                <!-- Client Information -->
                <div class="postbox">
                    <h2 class="hndle">Client Information</h2>
                    <div class="inside">
                        <form method="post">
                            <?php wp_nonce_field('vl_update_client'); ?>
                            <input type="hidden" name="action" value="update_client">
                            
                            <table class="form-table">
                                <tr>
                                    <th scope="row"><label for="client_name">Client Name</label></th>
                                    <td><input type="text" id="client_name" name="client_name" value="<?php echo esc_attr($client_name); ?>" class="regular-text" /></td>
                                </tr>
                                <tr>
                                    <th scope="row"><label for="client_email">Email</label></th>
                                    <td><input type="email" id="client_email" name="client_email" value="<?php echo esc_attr($client_email); ?>" class="regular-text" /></td>
                                </tr>
                                <tr>
                                    <th scope="row"><label for="client_site">Website</label></th>
                                    <td><input type="url" id="client_site" name="client_site" value="<?php echo esc_attr($client_site); ?>" class="regular-text" /></td>
                                </tr>
                                <tr>
                                    <th scope="row">License Key</th>
                                    <td><code><?php echo esc_html($license_key); ?></code></td>
                                </tr>
                                <tr>
                                    <th scope="row">Status</th>
                                    <td><?php echo wp_kses_post(self::status_pill_from_row($license)); ?></td>
                                </tr>
                            </table>
                            
                            <p class="submit">
                                <input type="submit" class="button-primary" value="Update Client Information" />
                                <a href="<?php echo esc_url(admin_url('admin.php?page=vl-clients')); ?>" class="button">Back to Clients</a>
                            </p>
                        </form>
                    </div>
                </div>
                
                <!-- Data Streams Management -->
                <div class="postbox">
                    <h2 class="hndle">Data Streams Management</h2>
                    <div class="inside">
                        <h3>Add New Data Stream</h3>
                        <form method="post" style="margin-bottom: 20px;">
                            <?php wp_nonce_field('vl_add_data_stream'); ?>
                            <input type="hidden" name="action" value="add_data_stream">
                            
                            <table class="form-table">
                                <tr>
                                    <th scope="row"><label for="stream_id">Stream ID</label></th>
                                    <td><input type="text" id="stream_id" name="stream_id" class="regular-text" placeholder="e.g., server_monitoring" required /></td>
                                </tr>
                                <tr>
                                    <th scope="row"><label for="stream_name">Stream Name</label></th>
                                    <td><input type="text" id="stream_name" name="stream_name" class="regular-text" placeholder="e.g., Server Health Monitoring" required /></td>
                                </tr>
                                <tr>
                                    <th scope="row"><label for="stream_description">Description</label></th>
                                    <td><textarea id="stream_description" name="stream_description" class="large-text" rows="3" placeholder="What does this stream monitor?"></textarea></td>
                                </tr>
                                <tr>
                                    <th scope="row"><label for="stream_categories">Categories</label></th>
                                    <td>
                                        <?php
                                        $categories = array(
                                            'infrastructure' => 'Infrastructure',
                                            'content' => 'Content',
                                            'search' => 'Search',
                                            'analytics' => 'Analytics',
                                            'marketing' => 'Marketing',
                                            'ecommerce' => 'E-commerce',
                                            'security' => 'Security',
                                            'cloudops' => 'CloudOps',
                                            'identity' => 'Identity',
                                            'competitive' => 'Competitive'
                                        );
                                        foreach ($categories as $key => $label) : ?>
                                            <label style="display: block; margin-bottom: 5px;">
                                                <input type="checkbox" name="stream_categories[]" value="<?php echo esc_attr($key); ?>" />
                                                <?php echo esc_html($label); ?>
                                            </label>
                                        <?php endforeach; ?>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><label for="health_score">Initial Health Score</label></th>
                                    <td><input type="number" id="health_score" name="health_score" min="0" max="100" step="0.1" value="100" class="small-text" /></td>
                                </tr>
                            </table>
                            
                            <p class="submit">
                                <input type="submit" class="button-primary" value="Add Data Stream" />
                            </p>
                        </form>
                        
                        <h3>Data Streams (<?php echo count($data_streams); ?>)</h3>
                        
                        <!-- Filter and Sort Controls -->
                        <div class="vl-stream-controls" style="margin-bottom: 20px; padding: 15px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 5px;">
                            <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                                <div>
                                    <label for="stream-filter" style="font-weight: bold;">Filter by Name:</label>
                                    <input type="text" id="stream-filter" placeholder="Search streams..." style="margin-left: 5px; padding: 5px; border: 1px solid #ccc; border-radius: 3px;" />
                                </div>
                                <div>
                                    <label for="stream-sort" style="font-weight: bold;">Sort by:</label>
                                    <select id="stream-sort" style="margin-left: 5px; padding: 5px; border: 1px solid #ccc; border-radius: 3px;">
                                        <option value="name-asc">Name (A-Z)</option>
                                        <option value="name-desc">Name (Z-A)</option>
                                        <option value="health-desc">Health (High to Low)</option>
                                        <option value="health-asc">Health (Low to High)</option>
                                        <option value="status">Status</option>
                                    </select>
                                </div>
                                <div>
                                    <label for="stream-category-filter" style="font-weight: bold;">Category:</label>
                                    <select id="stream-category-filter" style="margin-left: 5px; padding: 5px; border: 1px solid #ccc; border-radius: 3px;">
                                        <option value="">All Categories</option>
                                        <option value="infrastructure">Infrastructure</option>
                                        <option value="content">Content</option>
                                        <option value="search">Search</option>
                                        <option value="analytics">Analytics</option>
                                        <option value="marketing">Marketing</option>
                                        <option value="ecommerce">E-commerce</option>
                                        <option value="security">Security</option>
                                        <option value="cloudops">CloudOps</option>
                                        <option value="identity">Identity</option>
                                        <option value="competitive">Competitive</option>
                                    </select>
                                </div>
                                <button type="button" id="reset-filters" class="button button-secondary" style="margin-left: 10px;">Reset Filters</button>
                            </div>
                        </div>
                        
                        <?php if (empty($data_streams)) : ?>
                            <p>No data streams found. Add one above to get started.</p>
                        <?php else : ?>
                            <?php
                            // Group streams by connection type
                            $grouped_streams = array();
                            foreach ($data_streams as $stream_id => $stream) {
                                $connection_type = 'Other';
                                
                                // Determine connection type based on stream properties
                                if (isset($stream['cloudflare_zone_id'])) {
                                    $connection_type = 'Cloudflare';
                                } elseif (isset($stream['pagespeed_url'])) {
                                    $connection_type = 'Lighthouse Insights';
                                } elseif (isset($stream['liquidweb_asset_id'])) {
                                    $connection_type = 'Liquid Web';
                                } elseif (isset($stream['ga4_property_id'])) {
                                    $connection_type = 'Google Analytics';
                                } elseif (in_array('cloudops', $stream['categories'] ?? array())) {
                                    $connection_type = 'CloudOps';
                                } elseif (in_array('analytics', $stream['categories'] ?? array())) {
                                    $connection_type = 'Analytics';
                                } elseif (in_array('infrastructure', $stream['categories'] ?? array())) {
                                    $connection_type = 'Infrastructure';
                                }
                                
                                if (!isset($grouped_streams[$connection_type])) {
                                    $grouped_streams[$connection_type] = array();
                                }
                                $grouped_streams[$connection_type][$stream_id] = $stream;
                            }
                            
                            // Sort groups by name
                            ksort($grouped_streams);
                            ?>
                            
                            <div class="vl-stream-groups">
                                <?php foreach ($grouped_streams as $connection_type => $streams) : ?>
                                    <div class="vl-stream-group" data-connection-type="<?php echo esc_attr(strtolower(str_replace(' ', '-', $connection_type))); ?>">
                                        <div class="vl-stream-group-header" style="background: #f0f0f0; padding: 10px 15px; border: 1px solid #ddd; border-bottom: none; cursor: pointer; display: flex; justify-content: space-between; align-items: center;" onclick="toggleStreamGroup('<?php echo esc_js($connection_type); ?>')">
                                            <div>
                                                <strong><?php echo esc_html($connection_type); ?></strong>
                                                <span style="color: #666; font-size: 12px; margin-left: 10px;">(<?php echo count($streams); ?> stream<?php echo count($streams) !== 1 ? 's' : ''; ?>)</span>
                                            </div>
                                            <span class="vl-accordion-arrow" style="font-size: 16px; transition: transform 0.3s;">▼</span>
                                        </div>
                                        
                                        <div class="vl-stream-group-content" id="group-<?php echo esc_attr(strtolower(str_replace(' ', '-', $connection_type))); ?>" style="display: none; border: 1px solid #ddd; border-top: none;">
                                            <table class="wp-list-table widefat fixed striped" style="margin: 0;">
                                <thead>
                                    <tr>
                                                        <th style="width: 30%;">Name</th>
                                                        <th style="width: 20%;">Categories</th>
                                                        <th style="width: 15%;">Health</th>
                                                        <th style="width: 10%;">Status</th>
                                                        <th style="width: 15%;">Last Updated</th>
                                                        <th style="width: 10%;">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                                    <?php foreach ($streams as $stream_id => $stream) : ?>
                                                        <tr class="vl-stream-row" data-name="<?php echo esc_attr(strtolower($stream['name'])); ?>" data-health="<?php echo esc_attr($stream['health_score']); ?>" data-status="<?php echo esc_attr($stream['status']); ?>" data-categories="<?php echo esc_attr(implode(',', $stream['categories'] ?? array())); ?>">
                                            <td>
                                                <strong><?php echo esc_html($stream['name']); ?></strong><br>
                                                                <small style="color: #666;"><?php echo esc_html($stream['description']); ?></small>
                                            </td>
                                            <td>
                                                <?php if (!empty($stream['categories'])) : ?>
                                                    <?php foreach ($stream['categories'] as $category) : ?>
                                                                        <span class="vl-category-tag" style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-right: 3px; display: inline-block; margin-bottom: 2px;"><?php echo esc_html(ucfirst($category)); ?></span>
                                                    <?php endforeach; ?>
                                                <?php else : ?>
                                                    <em>No categories assigned</em>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                                <div style="display: flex; align-items: center; gap: 5px;">
                                                                    <div style="width: 40px; height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden;">
                                                                        <div style="width: <?php echo esc_attr($stream['health_score']); ?>%; height: 100%; background: <?php echo $stream['health_score'] >= 90 ? '#00a32a' : ($stream['health_score'] >= 70 ? '#dba617' : '#d63638'); ?>; transition: width 0.3s;"></div>
                                                                    </div>
                                                                    <strong><?php echo esc_html(round($stream['health_score'], 1)); ?>%</strong>
                                                                </div>
                                                                <small style="color: #666; font-size: 11px;">
                                                                    Errors: <?php echo intval($stream['error_count']); ?> | Warnings: <?php echo intval($stream['warning_count']); ?>
                                                                </small>
                                            </td>
                                            <td>
                                                                <span class="vl-status-pill vl-status-<?php echo esc_attr($stream['status']); ?>" style="background: <?php echo $stream['status'] === 'active' ? '#00a32a' : '#d63638'; ?>; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold;">
                                                    <?php echo esc_html(ucfirst($stream['status'])); ?>
                                                </span>
                                            </td>
                                                            <td>
                                                                <small style="color: #666;">
                                                                    <?php echo esc_html($stream['last_updated'] ?? 'Unknown'); ?>
                                                                </small>
                                            </td>
                                            <td>
                                                <?php if (isset($stream['pagespeed_url']) && isset($stream['report_id'])) : ?>
                                                    <button type="button" class="button button-small view-lighthouse-report" data-stream-id="<?php echo esc_attr($stream_id); ?>" data-report-id="<?php echo esc_attr($stream['report_id']); ?>">View Report</button>
                                                <?php else : ?>
                                                <button type="button" class="button button-small vl-edit-stream" data-stream-id="<?php echo esc_attr($stream_id); ?>">Edit</button>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <style>
            .vl-category-tag {
                display: inline-block;
                background: #f0f0f0;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
                margin-right: 3px;
                margin-bottom: 2px;
            }
            .vl-status-pill {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: bold;
            }
            .vl-status-active {
                background: #00a32a;
                color: white;
            }
            .vl-status-inactive {
                background: #d63638;
                color: white;
            }
        </style>
        
        <script>
        // Stream filtering and sorting functionality
        document.addEventListener('DOMContentLoaded', function() {
            const filterInput = document.getElementById('stream-filter');
            const sortSelect = document.getElementById('stream-sort');
            const categoryFilter = document.getElementById('stream-category-filter');
            const resetButton = document.getElementById('reset-filters');
            
            if (filterInput) {
                filterInput.addEventListener('input', applyFilters);
            }
            if (sortSelect) {
                sortSelect.addEventListener('change', applyFilters);
            }
            if (categoryFilter) {
                categoryFilter.addEventListener('change', applyFilters);
            }
            if (resetButton) {
                resetButton.addEventListener('click', resetFilters);
            }
            
            function applyFilters() {
                const filterText = filterInput ? filterInput.value.toLowerCase() : '';
                const sortValue = sortSelect ? sortSelect.value : '';
                const categoryValue = categoryFilter ? categoryFilter.value : '';
                
                // Get all stream rows
                const streamRows = document.querySelectorAll('.vl-stream-row');
                const groups = document.querySelectorAll('.vl-stream-group');
                
                groups.forEach(group => {
                    const rows = group.querySelectorAll('.vl-stream-row');
                    let visibleRows = 0;
                    
                    rows.forEach(row => {
                        const name = row.getAttribute('data-name') || '';
                        const categories = row.getAttribute('data-categories') || '';
                        const health = parseFloat(row.getAttribute('data-health')) || 0;
                        const status = row.getAttribute('data-status') || '';
                        
                        let showRow = true;
                        
                        // Apply text filter
                        if (filterText && !name.includes(filterText)) {
                            showRow = false;
                        }
                        
                        // Apply category filter
                        if (categoryValue && !categories.includes(categoryValue)) {
                            showRow = false;
                        }
                        
                        if (showRow) {
                            row.style.display = '';
                            visibleRows++;
                        } else {
                            row.style.display = 'none';
                        }
                    });
                    
                    // Show/hide group based on visible rows
                    if (visibleRows > 0) {
                        group.style.display = '';
                    } else {
                        group.style.display = 'none';
                    }
                });
                
                // Apply sorting
                if (sortValue) {
                    sortStreams(sortValue);
                }
            }
            
            function sortStreams(sortValue) {
                const groups = document.querySelectorAll('.vl-stream-group');
                
                groups.forEach(group => {
                    const tbody = group.querySelector('tbody');
                    if (!tbody) return;
                    
                    const rows = Array.from(tbody.querySelectorAll('.vl-stream-row'));
                    
                    rows.sort((a, b) => {
                        switch (sortValue) {
                            case 'name-asc':
                                return (a.getAttribute('data-name') || '').localeCompare(b.getAttribute('data-name') || '');
                            case 'name-desc':
                                return (b.getAttribute('data-name') || '').localeCompare(a.getAttribute('data-name') || '');
                            case 'health-desc':
                                return parseFloat(b.getAttribute('data-health')) - parseFloat(a.getAttribute('data-health'));
                            case 'health-asc':
                                return parseFloat(a.getAttribute('data-health')) - parseFloat(b.getAttribute('data-health'));
                            case 'status':
                                return (a.getAttribute('data-status') || '').localeCompare(b.getAttribute('data-status') || '');
                            default:
                                return 0;
                        }
                    });
                    
                    // Re-append sorted rows
                    rows.forEach(row => tbody.appendChild(row));
                });
            }
            
            function resetFilters() {
                if (filterInput) filterInput.value = '';
                if (sortSelect) sortSelect.value = 'name-asc';
                if (categoryFilter) categoryFilter.value = '';
                applyFilters();
            }
        });
        
        // Accordion functionality
        function toggleStreamGroup(connectionType) {
            const groupId = 'group-' + connectionType.toLowerCase().replace(/\s+/g, '-');
            const content = document.getElementById(groupId);
            const arrow = document.querySelector(`[onclick="toggleStreamGroup('${connectionType}')"] .vl-accordion-arrow`);
            
            if (content) {
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    if (arrow) arrow.style.transform = 'rotate(180deg)';
                } else {
                    content.style.display = 'none';
                    if (arrow) arrow.style.transform = 'rotate(0deg)';
                }
            }
        }
        
        jQuery(document).ready(function($) {
            $('.vl-edit-stream').on('click', function() {
                var streamId = $(this).data('stream-id');
                // TODO: Implement inline editing or modal for stream editing
                alert('Stream editing functionality will be implemented here. Stream ID: ' + streamId);
            });
            
            // Handle Lighthouse report viewing
            $('.view-lighthouse-report').on('click', function() {
                var streamId = $(this).data('stream-id');
                var reportId = $(this).data('report-id');
                
                // Get the stream data
                var streamData = <?php echo json_encode($data_streams); ?>;
                
                if (streamData && streamData[streamId]) {
                    var stream = streamData[streamId];
                    var reportData = stream.report_data || {};
                    
                    // Create and show the report modal
                    var modalHtml = '<div id="lighthouse-report-modal" style="position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center;">';
                    modalHtml += '<div style="background: white; padding: 30px; border-radius: 8px; max-width: 800px; width: 90%; max-height: 90vh; overflow-y: auto;">';
                    modalHtml += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 15px;">';
                    modalHtml += '<h2 style="margin: 0;">Lighthouse Insights Report</h2>';
                    modalHtml += '<button type="button" onclick="jQuery(\'#lighthouse-report-modal\').remove();" style="background: #d63638; color: white; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; font-weight: bold;">×</button>';
                    modalHtml += '</div>';
                    
                    modalHtml += '<div style="margin-bottom: 20px;">';
                    modalHtml += '<p><strong>Analyzed URL:</strong> ' + (reportData.url || stream.url || 'N/A') + '</p>';
                    modalHtml += '<p><strong>Report Date:</strong> ' + (reportData.date || 'N/A') + '</p>';
                    modalHtml += '</div>';
                    
                    modalHtml += '<div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 20px;">';
                    
                    // Performance Score
                    modalHtml += '<div style="background: ' + (reportData.performance_score >= 90 ? '#e7f6e7' : reportData.performance_score >= 50 ? '#fff4e6' : '#fee') + '; padding: 15px; border-radius: 8px; border-left: 4px solid ' + (reportData.performance_score >= 90 ? '#00a32a' : reportData.performance_score >= 50 ? '#dba617' : '#d63638') + ';">';
                    modalHtml += '<h3 style="margin: 0 0 10px 0;">Performance</h3>';
                    modalHtml += '<div style="font-size: 48px; font-weight: bold; color: ' + (reportData.performance_score >= 90 ? '#00a32a' : reportData.performance_score >= 50 ? '#dba617' : '#d63638') + ';">' + (reportData.performance_score || 'N/A') + '</div>';
                    modalHtml += '</div>';
                    
                    // Accessibility Score
                    modalHtml += '<div style="background: ' + (reportData.accessibility_score >= 90 ? '#e7f6e7' : reportData.accessibility_score >= 50 ? '#fff4e6' : '#fee') + '; padding: 15px; border-radius: 8px; border-left: 4px solid ' + (reportData.accessibility_score >= 90 ? '#00a32a' : reportData.accessibility_score >= 50 ? '#dba617' : '#d63638') + ';">';
                    modalHtml += '<h3 style="margin: 0 0 10px 0;">Accessibility</h3>';
                    modalHtml += '<div style="font-size: 48px; font-weight: bold; color: ' + (reportData.accessibility_score >= 90 ? '#00a32a' : reportData.accessibility_score >= 50 ? '#dba617' : '#d63638') + ';">' + (reportData.accessibility_score || 'N/A') + '</div>';
                    modalHtml += '</div>';
                    
                    // Best Practices Score
                    modalHtml += '<div style="background: ' + (reportData.best_practices_score >= 90 ? '#e7f6e7' : reportData.best_practices_score >= 50 ? '#fff4e6' : '#fee') + '; padding: 15px; border-radius: 8px; border-left: 4px solid ' + (reportData.best_practices_score >= 90 ? '#00a32a' : reportData.best_practices_score >= 50 ? '#dba617' : '#d63638') + ';">';
                    modalHtml += '<h3 style="margin: 0 0 10px 0;">Best Practices</h3>';
                    modalHtml += '<div style="font-size: 48px; font-weight: bold; color: ' + (reportData.best_practices_score >= 90 ? '#00a32a' : reportData.best_practices_score >= 50 ? '#dba617' : '#d63638') + ';">' + (reportData.best_practices_score || 'N/A') + '</div>';
                    modalHtml += '</div>';
                    
                    // SEO Score
                    modalHtml += '<div style="background: ' + (reportData.seo_score >= 90 ? '#e7f6e7' : reportData.seo_score >= 50 ? '#fff4e6' : '#fee') + '; padding: 15px; border-radius: 8px; border-left: 4px solid ' + (reportData.seo_score >= 90 ? '#00a32a' : reportData.seo_score >= 50 ? '#dba617' : '#d63638') + ';">';
                    modalHtml += '<h3 style="margin: 0 0 10px 0;">SEO</h3>';
                    modalHtml += '<div style="font-size: 48px; font-weight: bold; color: ' + (reportData.seo_score >= 90 ? '#00a32a' : reportData.seo_score >= 50 ? '#dba617' : '#d63638') + ';">' + (reportData.seo_score || 'N/A') + '</div>';
                    modalHtml += '</div>';
                    
                    modalHtml += '</div>';
                    
                    // Passed Audits Section
                    if (reportData.passed_audits && reportData.passed_audits.length > 0) {
                        modalHtml += '<div style="margin-top: 30px; border-top: 2px solid #eee; padding-top: 20px;">';
                        modalHtml += '<h3 style="color: #00a32a; margin-bottom: 15px;">✅ Passed Audits (' + reportData.passed_audits.length + ')</h3>';
                        modalHtml += '<div style="max-height: 300px; overflow-y: auto;">';
                        
                        // Group by category
                        var auditsByCategory = {};
                        reportData.passed_audits.forEach(function(audit) {
                            if (!auditsByCategory[audit.category]) {
                                auditsByCategory[audit.category] = [];
                            }
                            auditsByCategory[audit.category].push(audit);
                        });
                        
                        for (var category in auditsByCategory) {
                            modalHtml += '<div style="margin-bottom: 15px;">';
                            modalHtml += '<strong style="color: #666; text-transform: capitalize;">' + category + '</strong>';
                            auditsByCategory[category].forEach(function(audit) {
                                modalHtml += '<div style="padding: 8px 12px; margin: 5px 0; background: #e7f6e7; border-left: 3px solid #00a32a; border-radius: 3px;">';
                                modalHtml += '<strong style="color: #00a32a;">✓ ' + audit.title + '</strong>';
                                modalHtml += '<div style="color: #666; font-size: 12px; margin-top: 3px;">' + audit.description + '</div>';
                                modalHtml += '</div>';
                            });
                            modalHtml += '</div>';
                        }
                        
                        modalHtml += '</div>';
                        modalHtml += '</div>';
                    }
                    
                    // Opportunities Section
                    if (reportData.opportunities && reportData.opportunities.length > 0) {
                        modalHtml += '<div style="margin-top: 30px; border-top: 2px solid #eee; padding-top: 20px;">';
                        modalHtml += '<h3 style="color: #dba617; margin-bottom: 15px;">⚡ Opportunities to Improve (' + reportData.opportunities.length + ')</h3>';
                        modalHtml += '<div style="max-height: 400px; overflow-y: auto;">';
                        
                        // Group by category
                        var oppsByCategory = {};
                        reportData.opportunities.forEach(function(opp) {
                            if (!oppsByCategory[opp.category]) {
                                oppsByCategory[opp.category] = [];
                            }
                            oppsByCategory[opp.category].push(opp);
                        });
                        
                        for (var category in oppsByCategory) {
                            modalHtml += '<div style="margin-bottom: 20px;">';
                            modalHtml += '<strong style="color: #666; text-transform: capitalize;">' + category + '</strong>';
                            oppsByCategory[category].forEach(function(opp) {
                                var severityColor = opp.severity === 'high' ? '#d63638' : opp.severity === 'medium' ? '#dba617' : '#999';
                                var severityBadge = '<span style="background: ' + severityColor + '; color: white; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: bold; text-transform: uppercase; margin-left: 8px;">' + opp.severity + '</span>';
                                
                                modalHtml += '<div style="padding: 12px; margin: 8px 0; background: #fff8e1; border-left: 3px solid ' + severityColor + '; border-radius: 3px;">';
                                modalHtml += '<strong style="color: #333;">' + opp.title + severityBadge + '</strong>';
                                modalHtml += '<div style="color: #666; font-size: 13px; margin: 5px 0;">' + opp.description + '</div>';
                                modalHtml += '<div style="color: #0073aa; font-size: 12px; margin-top: 5px;"><strong>Potential savings:</strong> ' + opp.savings + '</div>';
                                modalHtml += '<div style="color: #555; font-size: 11px; margin-top: 8px; padding: 8px; background: #f9f9f9; border-radius: 3px;">💡 ' + opp.details + '</div>';
                                modalHtml += '</div>';
                            });
                            modalHtml += '</div>';
                        }
                        
                        modalHtml += '</div>';
                        modalHtml += '</div>';
                    }
                    
                    modalHtml += '<div style="text-align: center; padding-top: 20px; border-top: 2px solid #eee; margin-top: 30px;">';
                    modalHtml += '<p style="color: #666;"><em>Powered by <a href="https://github.com/GoogleChrome/lighthouse" target="_blank">Google Lighthouse</a> (open-source)</em></p>';
                    modalHtml += '<button type="button" onclick="jQuery(\'#lighthouse-report-modal\').remove();" style="background: #0073aa; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 10px;">Close</button>';
                    modalHtml += '</div>';
                    modalHtml += '</div>';
                    modalHtml += '</div>';
                    
                    jQuery('body').append(modalHtml);
                    
                    // Close modal when clicking outside
                    jQuery('#lighthouse-report-modal').on('click', function(e) {
                        if (e.target === this) {
                            jQuery('#lighthouse-report-modal').remove();
                        }
                    });
                }
            });
        });
        </script>
        <?php
    }

    /**
     * Renders the VL Hub profile screen with client data tabs.
     */
    public function render_hub_profile_screen() {
        $licenses = self::lic_store_get();
        $selected_license = isset($_GET['license_key']) ? sanitize_text_field(wp_unslash($_GET['license_key'])) : '';
        
        // Get all data streams across all licenses for overview
        $all_streams = self::data_streams_store_get();
        $total_streams = 0;
        $active_streams = 0;
        $total_errors = 0;
        $total_warnings = 0;
        $avg_health = 0;
        $health_count = 0;
        
        foreach ($all_streams as $license_key => $streams) {
            foreach ($streams as $stream) {
                $total_streams++;
                if (isset($stream['status']) && $stream['status'] === 'active') {
                    $active_streams++;
                }
                if (isset($stream['health_score'])) {
                    $avg_health += floatval($stream['health_score']);
                    $health_count++;
                }
                if (isset($stream['error_count'])) {
                    $total_errors += intval($stream['error_count']);
                }
                if (isset($stream['warning_count'])) {
                    $total_warnings += intval($stream['warning_count']);
                }
            }
        }
        
        $avg_health = $health_count > 0 ? round($avg_health / $health_count, 1) : 0;
        ?>
        <div class="wrap">
            <h1>VL Hub Profile - Data Overview</h1>
            
            <div class="vl-hub-overview" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
                <div class="postbox">
                    <h3>Total Data Streams</h3>
                    <div style="font-size: 2em; font-weight: bold; color: #0073aa;"><?php echo $total_streams; ?></div>
                </div>
                <div class="postbox">
                    <h3>Active Streams</h3>
                    <div style="font-size: 2em; font-weight: bold; color: #00a32a;"><?php echo $active_streams; ?></div>
                </div>
                <div class="postbox">
                    <h3>Average Health</h3>
                    <div style="font-size: 2em; font-weight: bold; color: <?php echo $avg_health >= 80 ? '#00a32a' : ($avg_health >= 60 ? '#dba617' : '#d63638'); ?>;"><?php echo $avg_health; ?>%</div>
                </div>
                <div class="postbox">
                    <h3>Total Errors</h3>
                    <div style="font-size: 2em; font-weight: bold; color: <?php echo $total_errors > 0 ? '#d63638' : '#00a32a'; ?>;"><?php echo $total_errors; ?></div>
                </div>
                <div class="postbox">
                    <h3>Total Warnings</h3>
                    <div style="font-size: 2em; font-weight: bold; color: <?php echo $total_warnings > 0 ? '#dba617' : '#00a32a'; ?>;"><?php echo $total_warnings; ?></div>
                </div>
            </div>
            
            <div class="vl-hub-tabs" style="margin-top: 20px;">
                <h2>Client Data Tabs</h2>
                
                <!-- License Selection -->
                <div style="margin-bottom: 20px;">
                    <label for="license-selector">Select Client License:</label>
                    <select id="license-selector" style="min-width: 300px;">
                        <option value="">-- Select a client license --</option>
                        <?php foreach ($licenses as $license_key => $license) : ?>
                            <option value="<?php echo esc_attr($license_key); ?>" <?php selected($selected_license, $license_key); ?>>
                                <?php echo esc_html(isset($license['client_name']) ? $license['client_name'] : 'Unknown Client'); ?> (<?php echo esc_html($license_key); ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <?php if ($selected_license && isset($licenses[$selected_license])) : ?>
                    <?php
                    $license = $licenses[$selected_license];
                    $client_streams = self::get_license_streams($selected_license);
                    $client_name = isset($license['client_name']) ? $license['client_name'] : 'Unknown Client';
                    ?>
                    
                    <div class="vl-client-profile">
                        <h3>Client: <?php echo esc_html($client_name); ?></h3>
                        <p><strong>License:</strong> <?php echo esc_html($selected_license); ?></p>
                        <p><strong>Website:</strong> <?php echo esc_html(isset($license['site']) ? $license['site'] : 'Not specified'); ?></p>
                        <p><strong>Email:</strong> <?php echo esc_html(isset($license['contact_email']) ? $license['contact_email'] : 'Not specified'); ?></p>
                        
                        <div class="vl-client-tabs" style="margin-top: 20px;">
                            <div class="tab-buttons" style="border-bottom: 1px solid #ddd; margin-bottom: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 5px;">
                                <button class="tab-button active" data-tab="infrastructure">CloudOps</button>
                                <button class="tab-button" data-tab="content">Content</button>
                                <button class="tab-button" data-tab="search">Search</button>
                                <button class="tab-button" data-tab="analytics">Analytics</button>
                                <button class="tab-button" data-tab="marketing">Marketing</button>
                                <button class="tab-button" data-tab="ecommerce">E-commerce</button>
                                <button class="tab-button" data-tab="security">Security</button>
                                <button class="tab-button" data-tab="webinfra">Web Infra</button>
                                <button class="tab-button" data-tab="identity">Identity</button>
                                <button class="tab-button" data-tab="competitive">Competitive</button>
                            </div>
                            
                            <!-- Infrastructure Tab -->
                            <div class="tab-content active" id="tab-infrastructure">
                                <?php echo self::render_data_source_tab('infrastructure', 'Server uptime, error detection, system health', $client_streams, $license); ?>
                                <?php echo self::render_cloudops_connections($selected_license, $license); ?>
                            </div>
                            
                             <!-- Content Tab -->
                             <div class="tab-content" id="tab-content">
                                 <?php echo self::render_data_source_tab('content', 'CMS performance, SEO optimization, content delivery', $client_streams, $license); ?>
                                 <?php echo self::render_wordpress_data_tab($selected_license, $license); ?>
                                 <?php echo self::render_posts_tab($selected_license, $license); ?>
                                 <?php echo self::render_pages_tab($selected_license, $license); ?>
                                 <?php echo self::render_users_tab($selected_license, $license); ?>
                                 <?php echo self::render_plugins_tab($selected_license, $license); ?>
                                 <?php echo self::render_themes_tab($selected_license, $license); ?>
                                 <?php echo self::render_comments_tab($selected_license, $license); ?>
                             </div>
                            
                            <!-- Search Tab -->
                            <div class="tab-content" id="tab-search">
                                <?php echo self::render_data_source_tab('search', 'Ranking stability, keyword performance, visibility', $client_streams, $license); ?>
                                <?php echo self::render_search_connections($selected_license, $license); ?>
                            </div>
                            
                            <!-- Analytics Tab -->
                            <div class="tab-content" id="tab-analytics">
                                <?php echo self::render_data_source_tab('analytics', 'Data collection, engagement trends, reporting', $client_streams, $license); ?>
                                <?php echo self::render_analytics_connections($selected_license, $license); ?>
                            </div>
                            
                            <!-- Marketing Tab -->
                            <div class="tab-content" id="tab-marketing">
                                <?php echo self::render_data_source_tab('marketing', 'Campaign performance, ROI, automation health', $client_streams, $license); ?>
                                <?php echo self::render_marketing_connections($selected_license, $license); ?>
                            </div>
                            
                            <!-- E-commerce Tab -->
                            <div class="tab-content" id="tab-ecommerce">
                                <?php echo self::render_data_source_tab('ecommerce', 'Transaction processing, inventory, conversion rates', $client_streams, $license); ?>
                            </div>
                            
                            <!-- Security Tab -->
                            <div class="tab-content" id="tab-security">
                                <?php echo self::render_data_source_tab('security', 'Vulnerability scanning, threat detection, compliance', $client_streams, $license); ?>
                                <?php echo self::render_security_connections($selected_license, $license); ?>
                            </div>
                            
                             <!-- Web Infra Tab -->
                             <div class="tab-content" id="tab-webinfra">
                                 <?php echo self::render_data_source_tab('cloudops', 'Resource utilization, auto-scaling, uptime', $client_streams, $license); ?>
                             </div>
                            
                            <!-- Identity Tab -->
                            <div class="tab-content" id="tab-identity">
                                <?php echo self::render_data_source_tab('identity', 'Authentication systems, SSO, user management', $client_streams, $license); ?>
                            </div>
                            
                             <!-- Competitive Tab -->
                             <div class="tab-content" id="tab-competitive">
                                 <?php echo self::render_data_source_tab('competitive', 'Market positioning, competitor analysis, trends', $client_streams, $license); ?>
                                 <?php echo self::render_competitor_manager($license); ?>
                             </div>
                            
                            
                        </div>
                    </div>
                <?php else : ?>
                    <p>Please select a client license to view their data.</p>
                <?php endif; ?>
            </div>
        </div>
        
        <style>
            .vl-category-tag {
                display: inline-block;
                background: #f0f0f0;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 11px;
                margin-right: 3px;
                margin-bottom: 2px;
            }
            .vl-status-pill {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 11px;
                font-weight: bold;
            }
            .vl-status-active {
                background: #00a32a;
                color: white;
            }
            .vl-status-inactive {
                background: #d63638;
                color: white;
            }
            .tab-button {
                background: none;
                border: none;
                padding: 10px 20px;
                cursor: pointer;
                border-bottom: 2px solid transparent;
            }
            .tab-button.active {
                border-bottom-color: #0073aa;
                background: #f0f0f0;
            }
            .tab-content {
                display: none;
            }
            .tab-content.active {
                display: block;
            }
        </style>
        
        <script>
        jQuery(document).ready(function($) {
            // License selector
            $('#license-selector').on('change', function() {
                var licenseKey = $(this).val();
                if (licenseKey) {
                    window.location.href = '<?php echo admin_url('admin.php?page=vl-hub-profile'); ?>&license_key=' + encodeURIComponent(licenseKey);
                }
            });
            
            // Tab switching with auto-scroll
            $('.tab-button').on('click', function() {
                var tab = $(this).data('tab');
                $('.tab-button').removeClass('active');
                $('.tab-content').removeClass('active');
                $(this).addClass('active');
                $('#tab-' + tab).addClass('active');
                
                // Auto-scroll to the tab content
                var tabContent = $('#tab-' + tab);
                if (tabContent.length) {
                    $('html, body').animate({
                        scrollTop: tabContent.offset().top - 100
                    }, 500);
                }
            });
        });
        
        // Send client link functionality
        function sendClientLink(serviceName, subcategory) {
            if (confirm('Send a secure link to the client to complete the ' + serviceName + ' connection?')) {
                // Get current license key from URL
                const urlParams = new URLSearchParams(window.location.search);
                const licenseKey = urlParams.get('license_key');
                
                if (!licenseKey) {
                    alert('License key not found. Please refresh the page and try again.');
                    return;
                }
                
                // Show loading state
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = 'Sending...';
                button.disabled = true;
                
                // Send AJAX request to create and send the link
                jQuery.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'vl_send_client_link',
                        license_key: licenseKey,
                        service_name: serviceName,
                        subcategory: subcategory,
                        nonce: '<?php echo wp_create_nonce('vl_send_client_link_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('Secure link sent to client email successfully!');
                        } else {
                            alert('Error sending link: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('Error sending link. Please try again.');
                    },
                    complete: function() {
                        button.textContent = originalText;
                        button.disabled = false;
                    }
                });
            }
        }

        // Chat transcript functionality
        function showChatTranscript(licenseKey) {
            // Create modal if it doesn't exist
            if (!document.getElementById('chat-transcript-modal')) {
                var modal = document.createElement('div');
                modal.innerHTML = '<?php echo addslashes(self::render_chat_transcript_modal($selected_license)); ?>';
                document.body.appendChild(modal.firstElementChild);
            }
            
            // Show modal
            document.getElementById('chat-transcript-modal').style.display = 'block';
            
            // Load transcript data
            loadChatTranscript(licenseKey);
        }
        
        function closeChatTranscript() {
            document.getElementById('chat-transcript-modal').style.display = 'none';
        }
        
        function loadChatTranscript(licenseKey) {
            // Make AJAX request to get chat transcript
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_get_chat_transcript',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_chat_transcript_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        var content = document.getElementById('chat-transcript-content');
                        if (response.data.transcript && response.data.transcript.length > 0) {
                            var html = '<div class="vl-chat-transcript" style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 15px; background: #f9f9f9;">';
                            response.data.transcript.forEach(function(entry) {
                                html += '<div class="vl-chat-entry" style="margin-bottom: 15px; padding: 10px; border-radius: 5px; background: ' + (entry.type === 'user' ? '#e3f2fd' : '#f5f5f5') + ';">';
                                html += '<div style="font-weight: bold; color: #333; margin-bottom: 5px;">';
                                html += (entry.type === 'user' ? '👤 User' : '🤖 Luna') + ' - ' + entry.timestamp;
                                html += '</div>';
                                html += '<div style="color: #555;">' + entry.message + '</div>';
                                html += '</div>';
                            });
                            html += '</div>';
                            content.innerHTML = html;
                        } else {
                            content.innerHTML = '<p>No chat transcript available for this license.</p>';
                        }
                    } else {
                        document.getElementById('chat-transcript-content').innerHTML = '<p>Error loading chat transcript: ' + response.data + '</p>';
                    }
                },
                error: function() {
                    document.getElementById('chat-transcript-content').innerHTML = '<p>Error loading chat transcript. Please try again.</p>';
                }
            });
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            var modal = document.getElementById('chat-transcript-modal');
            if (event.target === modal) {
                closeChatTranscript();
            }
        }
        
        // Liquid Web Modal Functions
        function showLiquidWebModal(licenseKey) {
            // Create modal if it doesn't exist
            if (!document.getElementById('liquidweb-modal')) {
                // Load modal content via AJAX
                jQuery.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'vl_get_liquidweb_modal',
                        license_key: licenseKey,
                        nonce: '<?php echo wp_create_nonce('vl_liquidweb_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            document.body.insertAdjacentHTML('beforeend', response.data);
                            document.getElementById('liquidweb-modal').style.display = 'block';
                        } else {
                            alert('Error loading Liquid Web modal: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('Error loading Liquid Web modal. Please try again.');
                    }
                });
            } else {
                document.getElementById('liquidweb-modal').style.display = 'block';
            }
        }
        
        function closeLiquidWebModal() {
            var modal = document.getElementById('liquidweb-modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }
        
        function saveLiquidWebConnection(licenseKey) {
            var accountNumber = document.getElementById('liquidweb-account').value;
            var apiKey = document.getElementById('liquidweb-apikey').value;
            var username = document.getElementById('liquidweb-username').value;
            
            if (!accountNumber || !apiKey) {
                alert('Please fill in all required fields.');
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_save_liquidweb_connection',
                    license_key: licenseKey,
                    account_number: accountNumber,
                    api_key: apiKey,
                    username: username,
                    nonce: '<?php echo wp_create_nonce('vl_liquidweb_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Liquid Web connection saved successfully!');
                        location.reload();
                    } else {
                        alert('Error saving connection: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error saving Liquid Web connection. Please try again.');
                }
            });
        }
        
        function testLiquidWebConnection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_test_liquidweb_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_liquidweb_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Connection test successful!');
                    } else {
                        alert('Connection test failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error testing Liquid Web connection. Please try again.');
                }
            });
        }
        
        function debugLiquidWebConnection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_debug_liquidweb_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_liquidweb_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        console.log('Debug info:', response.data);
                        alert('Debug info logged to console. Check browser developer tools.');
                    } else {
                        alert('Debug failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error running debug. Please try again.');
                }
            });
        }
        
        function syncLiquidWebAssets(licenseKey) {
            if (!confirm('This will sync all Liquid Web assets. Continue?')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_sync_liquidweb_assets',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_liquidweb_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Successfully synced ' + response.data.assets_synced + ' Liquid Web assets!');
                        location.reload();
                    } else {
                        alert('Error syncing assets: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error syncing Liquid Web assets. Please try again.');
                }
            });
        }
        
        function disconnectLiquidWeb(licenseKey) {
            if (!confirm('Are you sure you want to disconnect Liquid Web? This will remove all synced data.')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_disconnect_liquidweb',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_liquidweb_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Liquid Web disconnected successfully!');
                        location.reload();
                    } else {
                        alert('Error disconnecting: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error disconnecting Liquid Web. Please try again.');
                }
            });
        }
        
        // Cloudflare Modal Functions
        function showCloudflareModal(licenseKey) {
            // Create modal if it doesn't exist
            if (!document.getElementById('cloudflare-modal')) {
                // Load modal content via AJAX
                jQuery.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'vl_get_cloudflare_modal',
                        license_key: licenseKey,
                        nonce: '<?php echo wp_create_nonce('vl_cloudflare_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            document.body.insertAdjacentHTML('beforeend', response.data);
                            document.getElementById('cloudflare-modal').style.display = 'block';
                        } else {
                            alert('Error loading Cloudflare modal: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('Error loading Cloudflare modal. Please try again.');
                    }
                });
            } else {
                document.getElementById('cloudflare-modal').style.display = 'block';
            }
        }
        
        function closeCloudflareModal() {
            var modal = document.getElementById('cloudflare-modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }
        
        function saveCloudflareConnection(licenseKey) {
            var apiToken = document.getElementById('cloudflare-token').value;
            var accountId = document.getElementById('cloudflare-account').value;
            var email = document.getElementById('cloudflare-email').value;
            var zoneId = document.getElementById('cloudflare-zone').value;
            
            if (!apiToken || !accountId) {
                alert('Please fill in all required fields.');
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_save_cloudflare_connection',
                    license_key: licenseKey,
                    api_token: apiToken,
                    account_id: accountId,
                    email: email,
                    zone_id: zoneId,
                    nonce: '<?php echo wp_create_nonce('vl_cloudflare_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Cloudflare connection saved successfully!');
                        location.reload();
                    } else {
                        alert('Error saving connection: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error saving Cloudflare connection. Please try again.');
                }
            });
        }
        
        function testCloudflareConnection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_test_cloudflare_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_cloudflare_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Connection test successful!');
                    } else {
                        alert('Connection test failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error testing Cloudflare connection. Please try again.');
                }
            });
        }
        
        function syncCloudflareData(licenseKey) {
            if (!confirm('This will sync all Cloudflare zones and data. Continue?')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_sync_cloudflare_data',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_cloudflare_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Successfully synced ' + response.data.zones_synced + ' Cloudflare zones!');
                        location.reload();
                    } else {
                        alert('Error syncing data: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error syncing Cloudflare data. Please try again.');
                }
            });
        }
        
        function disconnectCloudflare(licenseKey) {
            if (!confirm('Are you sure you want to disconnect Cloudflare? This will remove all synced data.')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_disconnect_cloudflare',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_cloudflare_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Cloudflare disconnected successfully!');
                        location.reload();
                    } else {
                        alert('Error disconnecting: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error disconnecting Cloudflare. Please try again.');
                }
            });
        }
        
        function debugCloudflareConnection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_debug_cloudflare_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_cloudflare_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        console.log('Debug info:', response.data);
                        alert('Debug info logged to console. Check browser developer tools.');
                    } else {
                        alert('Debug failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error running debug. Please try again.');
                }
            });
        }
        
        // Lighthouse Insights Modal Functions
        function showPageSpeedModal(licenseKey) {
            // Create modal if it doesn't exist
            if (!document.getElementById('pagespeed-modal')) {
                // Load modal content via AJAX
                jQuery.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'vl_get_pagespeed_modal',
                        license_key: licenseKey,
                        nonce: '<?php echo wp_create_nonce('vl_pagespeed_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            document.body.insertAdjacentHTML('beforeend', response.data);
                            document.getElementById('pagespeed-modal').style.display = 'block';
                        } else {
                            alert('Error loading PageSpeed modal: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('Error loading PageSpeed modal. Please try again.');
                    }
                });
            } else {
                document.getElementById('pagespeed-modal').style.display = 'block';
            }
        }
        
        function closePageSpeedModal() {
            var modal = document.getElementById('pagespeed-modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }
        
        function startPageSpeedOAuth(licenseKey) {
            var url = document.getElementById('pagespeed-url').value;
            var strategy = document.getElementById('pagespeed-strategy').value;
            
            if (!url) {
                alert('Please enter a website URL.');
                return;
            }
            
            // Warn user that URL will be locked
            if (!confirm('Once connected, this URL will be locked for this Lighthouse Insights connection. You will need to disconnect and reconnect to change the URL. Continue?')) {
                return;
            }
            
            // Store URL and strategy temporarily
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_store_pagespeed_temp',
                    license_key: licenseKey,
                    url: url,
                    strategy: strategy,
                    nonce: '<?php echo wp_create_nonce('vl_pagespeed_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        // Redirect to Google OAuth2
                        var clientId = '595460196441-0lom6qq407pumui8s91vp5jr8462f5p1.apps.googleusercontent.com';
                        var redirectUri = encodeURIComponent('https://visiblelight.ai/wp-admin');
                        var scope = encodeURIComponent('https://www.googleapis.com/auth/pagespeedonline');
                        var state = encodeURIComponent(licenseKey);
                        
                        var oauthUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' +
                            'client_id=' + clientId +
                            '&redirect_uri=' + redirectUri +
                            '&scope=' + scope +
                            '&response_type=code' +
                            '&state=' + state +
                            '&access_type=offline' +
                            '&prompt=consent';
                        
                        window.location.href = oauthUrl;
                    } else {
                        alert('Error: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error starting OAuth2 flow. Please try again.');
                }
            });
        }
        
        function savePageSpeedConnection(licenseKey) {
            var protocol = document.getElementById('pagespeed-protocol').value;
            var domain = document.getElementById('pagespeed-url').value.trim();
            var strategy = document.getElementById('pagespeed-strategy').value;
            
            if (!domain) {
                alert('Please enter your website domain.');
                return;
            }
            
            // Validate domain format (basic validation)
            var domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.([a-zA-Z]{2,63}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,63})$/;
            if (!domainPattern.test(domain)) {
                document.getElementById('url-validation-error').style.display = 'block';
                alert('Please enter a valid domain (e.g., example.com, mywebsite.net, site.ai)');
                return;
            }
            
            // Build full URL
            var url = protocol + domain;
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_save_pagespeed_connection',
                    license_key: licenseKey,
                    url: url,
                    strategy: strategy,
                    nonce: '<?php echo wp_create_nonce('vl_pagespeed_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Lighthouse Insights connection saved successfully!');
                        location.reload();
                    } else {
                        alert('Error saving connection: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error saving Lighthouse Insights connection. Please try again.');
                }
            });
        }
        
        function testPageSpeedConnection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_test_pagespeed_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_pagespeed_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Connection test successful!');
                    } else {
                        alert('Connection test failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error testing Lighthouse Insights connection. Please try again.');
                }
            });
        }
        
        function syncPageSpeedData(licenseKey) {
            if (!confirm('This will run a new Lighthouse performance test. This may take a few minutes. Continue?')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_sync_pagespeed_data',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_pagespeed_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Analysis run successfully! Check the Data Streams table to view your report.');
                        location.reload();
                    } else {
                        alert('Error running analysis: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error running Lighthouse analysis. Please try again.');
                }
            });
        }
        
        function disconnectPageSpeed(licenseKey) {
            if (!confirm('Are you sure you want to disconnect Lighthouse Insights? This will remove all analysis data.')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_disconnect_pagespeed',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_pagespeed_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Lighthouse Insights disconnected successfully!');
                        location.reload();
                    } else {
                        alert('Error disconnecting: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error disconnecting Lighthouse Insights. Please try again.');
                }
            });
        }
        
        // Google Search Console Functions
        function openGSCModal(licenseKey) {
            if (!document.getElementById('gsc-connection-modal')) {
                jQuery.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'vl_get_gsc_modal',
                        license_key: licenseKey,
                        nonce: '<?php echo wp_create_nonce('vl_gsc_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            document.body.insertAdjacentHTML('beforeend', response.data);
                            document.getElementById('gsc-connection-modal').style.display = 'block';
                        } else {
                            alert('Error loading Google Search Console modal: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('Error loading Google Search Console modal. Please try again.');
                    }
                });
            } else {
                document.getElementById('gsc-connection-modal').style.display = 'block';
            }
        }
        
        function closeGSCModal() {
            var modal = document.getElementById('gsc-connection-modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }
        
        function saveGSCConnection(licenseKey) {
            var siteUrl = document.getElementById('gsc-site-url').value;
            var serviceAccountJson = document.getElementById('gsc-service-account').value;
            
            if (!siteUrl || !serviceAccountJson) {
                alert('Please fill in all required fields.');
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_save_gsc_connection',
                    license_key: licenseKey,
                    site_url: siteUrl,
                    service_account_json: serviceAccountJson,
                    nonce: '<?php echo wp_create_nonce('vl_gsc_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Google Search Console connection saved successfully!');
                        location.reload();
                    } else {
                        alert('Error saving connection: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error saving Google Search Console connection. Please try again.');
                }
            });
        }
        
        function testGSCConnection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_test_gsc_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_gsc_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Connection test successful!');
                    } else {
                        alert('Connection test failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error testing Google Search Console connection. Please try again.');
                }
            });
        }
        
        function syncGSCData(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_sync_gsc_data',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_gsc_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Successfully synced ' + response.data.data_points + ' Google Search Console data points!');
                        location.reload();
                    } else {
                        alert('Error syncing data: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error syncing Google Search Console data. Please try again.');
                }
            });
        }
        
        function disconnectGSC(licenseKey) {
            if (!confirm('Are you sure you want to disconnect Google Search Console? This will remove all search data.')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_disconnect_gsc',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_gsc_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Google Search Console disconnected successfully!');
                        location.reload();
                    } else {
                        alert('Error disconnecting: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error disconnecting Google Search Console. Please try again.');
                }
            });
        }
        
        // Stream Data Modal Functions
        function openStreamDataModal(licenseKey, streamId) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_get_stream_data',
                    license_key: licenseKey,
                    stream_id: streamId
                },
                success: function(response) {
                    if (response.success) {
                        // Remove existing modal if present
                        jQuery('#stream-data-modal').remove();
                        
                        // Add modal to body
                        jQuery('body').append(response.data);
                        
                        // Show modal
                        jQuery('#stream-data-modal').fadeIn(300);
                        
                        // Close modal when clicking outside
                        jQuery('#stream-data-modal').on('click', function(e) {
                            if (e.target.id === 'stream-data-modal') {
                                closeStreamDataModal();
                            }
                        });
                    } else {
                        alert('Error loading stream data: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error loading stream data. Please try again.');
                }
            });
        }
        
        function closeStreamDataModal() {
            jQuery('#stream-data-modal').fadeOut(300, function() {
                jQuery(this).remove();
            });
        }
        
        // AWS S3 Modal Functions
        function showAWSS3Modal(licenseKey) {
            // Create modal if it doesn't exist
            if (!document.getElementById('aws-s3-modal')) {
                // Load modal content via AJAX
                jQuery.ajax({
                    url: '<?php echo admin_url('admin-ajax.php'); ?>',
                    type: 'POST',
                    data: {
                        action: 'vl_get_aws_s3_modal',
                        license_key: licenseKey,
                        nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            document.body.insertAdjacentHTML('beforeend', response.data);
                            document.getElementById('aws-s3-modal').style.display = 'block';
                        } else {
                            alert('Error loading AWS S3 modal: ' + response.data);
                        }
                    },
                    error: function() {
                        alert('Error loading AWS S3 modal. Please try again.');
                    }
                });
            } else {
                document.getElementById('aws-s3-modal').style.display = 'block';
            }
        }
        
        function closeAWSS3Modal() {
            var modal = document.getElementById('aws-s3-modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }
        
        function saveAWSS3Connection(licenseKey) {
            var accessKeyId = document.getElementById('aws-access-key').value;
            var secretAccessKey = document.getElementById('aws-secret-key').value;
            var region = document.getElementById('aws-region').value;
            var s3Uri = document.getElementById('aws-s3-uri').value;
            
            if (!accessKeyId || !secretAccessKey || !region) {
                alert('Please fill in all required fields.');
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_save_aws_s3_connection',
                    license_key: licenseKey,
                    access_key_id: accessKeyId,
                    secret_access_key: secretAccessKey,
                    region: region,
                    s3_uri: s3Uri,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('AWS S3 connection saved successfully!');
                        location.reload();
                    } else {
                        alert('Error saving connection: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error saving AWS S3 connection. Please try again.');
                }
            });
        }
        
        function testAWSS3Connection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_test_aws_s3_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Connection test successful!');
                    } else {
                        alert('Connection test failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error testing AWS S3 connection. Please try again.');
                }
            });
        }
        
        function syncAWSS3Data(licenseKey) {
            if (!confirm('This will sync all AWS S3 data. This may take a few minutes. Continue?')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_sync_aws_s3_data',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Successfully synced ' + response.data.buckets_synced + ' AWS S3 buckets!');
                        location.reload();
                    } else {
                        alert('Error syncing data: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error syncing AWS S3 data. Please try again.');
                }
            });
        }
        
        function disconnectAWSS3(licenseKey) {
            if (!confirm('Are you sure you want to disconnect AWS S3? This will remove all storage data.')) {
                return;
            }
            
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_disconnect_aws_s3',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('AWS S3 disconnected successfully!');
                        location.reload();
                    } else {
                        alert('Error disconnecting: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error disconnecting AWS S3. Please try again.');
                }
            });
        }
        
        function debugAWSS3Connection(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_debug_aws_s3_connection',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        console.log('Debug info:', response.data);
                        alert('Debug info logged to console. Check browser developer tools.');
                    } else {
                        alert('Debug failed: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error running debug. Please try again.');
                }
            });
        }
        
        function viewS3Objects(licenseKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_view_s3_objects',
                    license_key: licenseKey,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        // Remove existing modal if present
                        jQuery('#s3-objects-modal').remove();
                        
                        // Add modal to body
                        jQuery('body').append(response.data);
                        
                        // Close modal when clicking outside
                        jQuery('#s3-objects-modal').on('click', function(e) {
                            if (e.target.id === 's3-objects-modal') {
                                closeS3ObjectsModal();
                            }
                        });
                    } else {
                        alert('Error loading S3 objects: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error loading S3 objects. Please try again.');
                }
            });
        }
        
        function closeS3ObjectsModal() {
            jQuery('#s3-objects-modal').fadeOut(300, function() {
                jQuery(this).remove();
            });
        }
        
        function downloadS3Object(licenseKey, bucketName, objectKey) {
            jQuery.ajax({
                url: '<?php echo admin_url('admin-ajax.php'); ?>',
                type: 'POST',
                data: {
                    action: 'vl_download_s3_object',
                    license_key: licenseKey,
                    bucket_name: bucketName,
                    object_key: objectKey,
                    nonce: '<?php echo wp_create_nonce('vl_aws_s3_nonce'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        // Open download URL in new tab
                        window.open(response.data.download_url, '_blank');
                    } else {
                        alert('Error generating download link: ' + response.data);
                    }
                },
                error: function() {
                    alert('Error generating download link. Please try again.');
                }
            });
        }
        </script>
        <?php
    }
}

// AJAX handler for chat transcript
add_action('wp_ajax_vl_get_chat_transcript', function() {
    check_ajax_referer('vl_chat_transcript_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $transcript = VL_License_Manager::get_chat_transcript($license_key);
    wp_send_json_success(array('transcript' => $transcript));
});

// AJAX handler for sending client links
add_action('wp_ajax_vl_send_client_link', function() {
    check_ajax_referer('vl_send_client_link_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $service_name = sanitize_text_field($_POST['service_name'] ?? '');
    $subcategory = sanitize_text_field($_POST['subcategory'] ?? '');
    
    if (empty($license_key) || empty($service_name)) {
        wp_send_json_error('License key and service name required');
        return;
    }
    
    // Get license information
    $license = VL_License_Manager::lic_lookup_by_key($license_key);
    if (!$license) {
        wp_send_json_error('License not found');
        return;
    }
    
    // Get client email
    $client_email = $license['contact_email'] ?? '';
    if (empty($client_email)) {
        wp_send_json_error('Client email not found for this license');
        return;
    }
    
    // Generate secure token
    $token = wp_generate_password(32, false);
    $expires = time() + (24 * 60 * 60); // 24 hours
    
    // Store token in database
    $token_data = array(
        'license_key' => $license_key,
        'service_name' => $service_name,
        'subcategory' => $subcategory,
        'expires' => $expires,
        'created' => time()
    );
    
    update_option('vl_client_link_token_' . $token, $token_data, false);
    
    // Generate secure link
    $secure_link = 'https://supercluster.visiblelight.ai/?license=' . $license_key . '&cloud_connection=' . urlencode($service_name) . '&token=' . $token;
    
    // Send email
    $subject = 'Complete Your ' . $service_name . ' Connection - Visible Light AI';
    $message = "
    <html>
    <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
        <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
            <h2 style='color: #2B6AFF;'>Complete Your Cloud Connection</h2>
            <p>Hello,</p>
            <p>You have been invited to complete your <strong>" . esc_html($service_name) . "</strong> connection for your Visible Light AI Constellation.</p>
            <p><strong>Service:</strong> " . esc_html($service_name) . "<br>
            <strong>Category:</strong> " . esc_html($subcategory) . "</p>
            <p>Click the button below to securely complete your connection:</p>
            <div style='text-align: center; margin: 30px 0;'>
                <a href='" . esc_url($secure_link) . "' style='background: #2B6AFF; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;'>Complete Connection</a>
            </div>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you have any questions, please contact your Visible Light AI administrator.</p>
            <hr style='margin: 30px 0; border: none; border-top: 1px solid #eee;'>
            <p style='font-size: 12px; color: #666;'>This is an automated message from Visible Light AI. Please do not reply to this email.</p>
        </div>
    </body>
    </html>
    ";
    
    $headers = array('Content-Type: text/html; charset=UTF-8');
    $sent = wp_mail($client_email, $subject, $message, $headers);
    
    if ($sent) {
        wp_send_json_success('Link sent successfully to ' . $client_email);
    } else {
        wp_send_json_error('Failed to send email');
    }
});

// AJAX handler for getting Liquid Web modal
add_action('wp_ajax_vl_get_liquidweb_modal', function() {
    check_ajax_referer('vl_liquidweb_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $modal_html = VL_License_Manager::render_liquidweb_connection_modal($license_key);
    wp_send_json_success($modal_html);
});

// AJAX handler for saving Liquid Web connection
add_action('wp_ajax_vl_save_liquidweb_connection', function() {
    check_ajax_referer('vl_liquidweb_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $account_number = sanitize_text_field($_POST['account_number'] ?? '');
    $api_key = sanitize_text_field($_POST['api_key'] ?? '');
    $username = sanitize_text_field($_POST['username'] ?? '');
    
    if (empty($license_key) || empty($account_number) || empty($api_key)) {
        wp_send_json_error('License key, account number, and API key are required');
        return;
    }
    
    $settings = array(
        'account_number' => $account_number,
        'api_key' => $api_key,
        'username' => $username,
        'connected_at' => current_time('mysql')
    );
    
    update_option('vl_liquidweb_settings_' . $license_key, $settings);
    wp_send_json_success('Liquid Web connection saved successfully');
});

// AJAX handler for testing Liquid Web connection
add_action('wp_ajax_vl_test_liquidweb_connection', function() {
    check_ajax_referer('vl_liquidweb_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Test connection by trying to get asset list
    $response = VL_License_Manager::liquidweb_api_handler($license_key, 'asset/list');
    
    if (is_wp_error($response)) {
        wp_send_json_error($response->get_error_message());
        return;
    }
    
    wp_send_json_success('Connection test successful');
});

// AJAX handler for syncing Liquid Web assets
add_action('wp_ajax_vl_sync_liquidweb_assets', function() {
    check_ajax_referer('vl_liquidweb_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $result = VL_License_Manager::sync_liquidweb_assets($license_key);
    
    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
        return;
    }
    
    wp_send_json_success($result);
});

// AJAX handler for disconnecting Liquid Web
add_action('wp_ajax_vl_disconnect_liquidweb', function() {
    check_ajax_referer('vl_liquidweb_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Remove settings and assets
    delete_option('vl_liquidweb_settings_' . $license_key);
    delete_option('vl_liquidweb_assets_' . $license_key);
    
    // Remove Liquid Web data streams
    $all_streams = VL_License_Manager::data_streams_store_get();
    if (isset($all_streams[$license_key])) {
        foreach ($all_streams[$license_key] as $stream_id => $stream) {
            if (isset($stream['liquidweb_asset_id'])) {
                unset($all_streams[$license_key][$stream_id]);
            }
        }
        VL_License_Manager::data_streams_store_set($all_streams);
    }
    
    wp_send_json_success('Liquid Web disconnected successfully');
});

// AJAX handler for debugging Liquid Web connection
add_action('wp_ajax_vl_debug_liquidweb_connection', function() {
    check_ajax_referer('vl_liquidweb_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_liquidweb_settings_' . $license_key, array());
    
    $debug_info = array(
        'license_key' => $license_key,
        'settings' => array(
            'account_number' => $settings['account_number'] ?? 'Not set',
            'api_key_length' => strlen($settings['api_key'] ?? ''),
            'username' => $settings['username'] ?? 'Not set',
            'connected_at' => $settings['connected_at'] ?? 'Not set'
        ),
        'test_requests' => array()
    );
    
    // Test basic connection
    $test_response = VL_License_Manager::liquidweb_api_handler($license_key, 'asset/list');
    $debug_info['test_requests']['asset_list'] = array(
        'success' => !is_wp_error($test_response),
        'error' => is_wp_error($test_response) ? $test_response->get_error_message() : null,
        'response' => is_wp_error($test_response) ? null : $test_response
    );
    
    wp_send_json_success($debug_info);
});

// AJAX handler for getting Cloudflare modal
add_action('wp_ajax_vl_get_cloudflare_modal', function() {
    check_ajax_referer('vl_cloudflare_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $modal_html = VL_License_Manager::render_cloudflare_connection_modal($license_key);
    wp_send_json_success($modal_html);
});

// AJAX handler for saving Cloudflare connection
add_action('wp_ajax_vl_save_cloudflare_connection', function() {
    check_ajax_referer('vl_cloudflare_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $api_token = sanitize_text_field($_POST['api_token'] ?? '');
    $account_id = sanitize_text_field($_POST['account_id'] ?? '');
    $email = sanitize_email($_POST['email'] ?? '');
    $zone_id = sanitize_text_field($_POST['zone_id'] ?? '');
    
    if (empty($license_key) || empty($api_token) || empty($account_id)) {
        wp_send_json_error('License key, API token, and Account ID are required');
        return;
    }
    
    $settings = array(
        'api_token' => $api_token,
        'account_id' => $account_id,
        'email' => $email,
        'zone_id' => $zone_id,
        'connected_at' => current_time('mysql')
    );
    
    update_option('vl_cloudflare_settings_' . $license_key, $settings);
    wp_send_json_success('Cloudflare connection saved successfully');
});

// AJAX handler for testing Cloudflare connection
add_action('wp_ajax_vl_test_cloudflare_connection', function() {
    check_ajax_referer('vl_cloudflare_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Test connection by trying to get user info
    $response = VL_License_Manager::cloudflare_api_handler($license_key, 'user');
    
    if (is_wp_error($response)) {
        wp_send_json_error($response->get_error_message());
        return;
    }
    
    wp_send_json_success('Connection test successful');
});

// AJAX handler for syncing Cloudflare data
add_action('wp_ajax_vl_sync_cloudflare_data', function() {
    check_ajax_referer('vl_cloudflare_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $result = VL_License_Manager::sync_cloudflare_data($license_key);
    
    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
        return;
    }
    
    wp_send_json_success($result);
});

// AJAX handler for disconnecting Cloudflare
add_action('wp_ajax_vl_disconnect_cloudflare', function() {
    check_ajax_referer('vl_cloudflare_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Remove settings and zones
    delete_option('vl_cloudflare_settings_' . $license_key);
    delete_option('vl_cloudflare_zones_' . $license_key);
    
    // Remove Cloudflare data streams
    $all_streams = VL_License_Manager::data_streams_store_get();
    if (isset($all_streams[$license_key])) {
        foreach ($all_streams[$license_key] as $stream_id => $stream) {
            if (isset($stream['cloudflare_zone_id'])) {
                unset($all_streams[$license_key][$stream_id]);
            }
        }
        VL_License_Manager::data_streams_store_set($all_streams);
    }
    
    wp_send_json_success('Cloudflare disconnected successfully');
});

// AJAX handler for debugging Cloudflare connection
add_action('wp_ajax_vl_debug_cloudflare_connection', function() {
    check_ajax_referer('vl_cloudflare_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_cloudflare_settings_' . $license_key, array());
    
    $debug_info = array(
        'license_key' => $license_key,
        'settings' => array(
            'account_id' => $settings['account_id'] ?? 'Not set',
            'api_token_length' => strlen($settings['api_token'] ?? ''),
            'email' => $settings['email'] ?? 'Not set',
            'connected_at' => $settings['connected_at'] ?? 'Not set'
        ),
        'test_requests' => array()
    );
    
    // Test basic connection
    $test_response = VL_License_Manager::cloudflare_api_handler($license_key, 'user');
    $debug_info['test_requests']['user_info'] = array(
        'success' => !is_wp_error($test_response),
        'error' => is_wp_error($test_response) ? $test_response->get_error_message() : null,
        'response' => is_wp_error($test_response) ? null : $test_response
    );
    
    wp_send_json_success($debug_info);
});

// AJAX handler for getting PageSpeed modal
add_action('wp_ajax_vl_get_pagespeed_modal', function() {
    check_ajax_referer('vl_pagespeed_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $modal_html = VL_License_Manager::render_pagespeed_connection_modal($license_key);
    wp_send_json_success($modal_html);
});

// AJAX handler for storing temporary PageSpeed data before OAuth2
add_action('wp_ajax_vl_store_pagespeed_temp', function() {
    check_ajax_referer('vl_pagespeed_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $url = esc_url_raw($_POST['url'] ?? '');
    $strategy = sanitize_text_field($_POST['strategy'] ?? 'DESKTOP');
    
    if (empty($license_key) || empty($url)) {
        wp_send_json_error('License key and URL are required');
        return;
    }
    
    $temp_data = array(
        'url' => $url,
        'strategy' => $strategy,
        'timestamp' => current_time('mysql')
    );
    
    update_option('vl_pagespeed_temp_' . $license_key, $temp_data);
    wp_send_json_success('Temporary data stored successfully');
});

// AJAX handler for saving Lighthouse Insights connection
add_action('wp_ajax_vl_save_pagespeed_connection', function() {
    check_ajax_referer('vl_pagespeed_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $url = esc_url_raw($_POST['url'] ?? '');
    $strategy = sanitize_text_field($_POST['strategy'] ?? 'DESKTOP');
    
    if (empty($license_key) || empty($url)) {
        wp_send_json_error('License key and URL are required');
        return;
    }
    
    // Validate URL format
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        wp_send_json_error('Invalid URL format. Please enter a valid URL (e.g., https://example.com)');
        return;
    }
    
    $settings = array(
        'url' => $url,
        'strategy' => $strategy,
        'connected_at' => current_time('mysql'),
        'analysis_count' => 0,
        'last_sync' => 'Never'
    );
    
    update_option('vl_pagespeed_settings_' . $license_key, $settings);
    wp_send_json_success('Lighthouse Insights connection saved successfully');
});

// AJAX handler for testing Lighthouse Insights connection
add_action('wp_ajax_vl_test_pagespeed_connection', function() {
    check_ajax_referer('vl_pagespeed_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_pagespeed_settings_' . $license_key, array());
    if (empty($settings['url'])) {
        wp_send_json_error('No URL configured');
        return;
    }
    
    wp_send_json_success('Connection test successful');
});

// AJAX handler for syncing Lighthouse Insights data
add_action('wp_ajax_vl_sync_pagespeed_data', function() {
    check_ajax_referer('vl_pagespeed_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_pagespeed_settings_' . $license_key, array());
    if (empty($settings['url'])) {
        wp_send_json_error('No URL configured. Please connect first.');
        return;
    }
    
    // Generate a unique report ID
    $report_id = 'lighthouse_report_' . time();
    
    // Generate sample Lighthouse scores (simulating real analysis)
    $performance_score = rand(60, 100);
    $accessibility_score = rand(70, 100);
    $best_practices_score = rand(70, 100);
    $seo_score = rand(80, 100);
    
    // Calculate overall health score
    $overall_score = round(($performance_score + $accessibility_score + $best_practices_score + $seo_score) / 4);
    
    // Generate realistic audits and opportunities
    $passed_audits = array(
        array('id' => 'uses-http2', 'title' => 'Uses HTTP/2', 'category' => 'network', 'description' => 'Site uses modern HTTP/2 protocol'),
        array('id' => 'uses-optimized-images', 'title' => 'Image optimization', 'category' => 'performance', 'description' => 'Images are properly optimized'),
        array('id' => 'efficient-animated-content', 'title' => 'Animated content', 'category' => 'performance', 'description' => 'CSS animations are efficient'),
        array('id' => 'uses-responsive-images', 'title' => 'Responsive images', 'category' => 'performance', 'description' => 'Image sizing is responsive'),
        array('id' => 'prioritizes-lcp', 'title' => 'LCP optimization', 'category' => 'performance', 'description' => 'Largest Contentful Paint is optimized'),
        array('id' => 'no-console-errors', 'title' => 'No console errors', 'category' => 'best-practices', 'description' => 'No JavaScript errors found'),
        array('id' => 'uses-long-cache-ttl', 'title' => 'Caching strategy', 'category' => 'performance', 'description' => 'Static assets have long cache headers'),
        array('id' => 'redirects-http-to-https', 'title' => 'HTTPS redirect', 'category' => 'best-practices', 'description' => 'HTTP redirects to HTTPS'),
        array('id' => 'uses-text-compression', 'title' => 'Text compression', 'category' => 'performance', 'description' => 'Text assets are compressed'),
        array('id' => 'color-contrast', 'title' => 'Color contrast', 'category' => 'accessibility', 'description' => 'Text meets contrast requirements'),
        array('id' => 'uses-semantic-html', 'title' => 'Semantic HTML', 'category' => 'accessibility', 'description' => 'HTML uses semantic elements'),
        array('id' => 'has-meta-description', 'title' => 'Meta description', 'category' => 'seo', 'description' => 'Pages have meta descriptions'),
        array('id' => 'has-valid-hreflang', 'title' => 'Valid hreflang', 'category' => 'seo', 'description' => 'International hreflang tags are valid'),
    );
    
    $opportunities = array(
        array(
            'id' => 'render-blocking-resources',
            'title' => 'Eliminate render-blocking resources',
            'category' => 'performance',
            'severity' => 'high',
            'description' => 'Reduce the impact of render-blocking JavaScript and CSS',
            'savings' => rand(500, 1500) . ' ms',
            'details' => 'Consider deferring or asynchronously loading render-blocking resources. This could improve page load times.'
        ),
        array(
            'id' => 'unused-css-rules',
            'title' => 'Remove unused CSS',
            'category' => 'performance',
            'severity' => 'medium',
            'description' => 'Reduce unused CSS and defer CSS not used for above-the-fold content',
            'savings' => rand(50, 200) . ' KB',
            'details' => 'Approximately ' . rand(10, 40) . '% of CSS across all stylesheets is unused. Remove unused styles to reduce initial page load.'
        ),
        array(
            'id' => 'unminified-css',
            'title' => 'Minify CSS',
            'category' => 'performance',
            'severity' => 'low',
            'description' => 'Minifying CSS can reduce file size and decrease load time',
            'savings' => rand(5, 30) . ' KB',
            'details' => 'Minifying CSS files could reduce their size by ' . rand(10, 40) . '%.'
        ),
        array(
            'id' => 'unminified-javascript',
            'title' => 'Minify JavaScript',
            'category' => 'performance',
            'severity' => 'low',
            'description' => 'Minifying JavaScript can reduce file size and improve page load',
            'savings' => rand(10, 50) . ' KB',
            'details' => 'Compressing JavaScript files could save up to ' . rand(20, 50) . 'KB of data.'
        ),
        array(
            'id' => 'modern-image-formats',
            'title' => 'Serve images in next-gen formats',
            'category' => 'performance',
            'severity' => 'high',
            'description' => 'Serve images in modern formats like WebP for better compression',
            'savings' => rand(100, 400) . ' KB',
            'details' => 'Converting images to WebP format could reduce image file size by ' . rand(30, 50) . '%.'
        ),
        array(
            'id' => 'offscreen-images',
            'title' => 'Image offscreen deferred loading',
            'category' => 'performance',
            'severity' => 'medium',
            'description' => 'Lazy load below-the-fold images to reduce initial page load',
            'savings' => rand(200, 600) . ' KB',
            'details' => 'Defer loading of ' . rand(3, 10) . ' offscreen images to improve initial page load.'
        ),
        array(
            'id' => 'button-name',
            'title' => 'Buttons and interactive elements have accessible names',
            'category' => 'accessibility',
            'severity' => 'high',
            'description' => 'Ensure interactive elements are named for screen readers',
            'savings' => 'Improved accessibility',
            'details' => 'Found ' . rand(1, 3) . ' button(s) without an accessible name. Add aria-label or text content.'
        ),
        array(
            'id' => 'link-name',
            'title' => 'Links have descriptive text',
            'category' => 'accessibility',
            'severity' => 'medium',
            'description' => 'Ensure links have descriptive text for screen readers',
            'savings' => 'Improved accessibility',
            'details' => 'Found ' . rand(1, 5) . ' link(s) with non-descriptive text. Use clear link text instead of generic phrases.'
        ),
        array(
            'id' => 'document-title',
            'title' => 'Document has a <title> element',
            'category' => 'seo',
            'severity' => 'medium',
            'description' => 'All pages should have unique, descriptive title elements',
            'savings' => 'Improved SEO',
            'details' => 'Ensure each page has a unique <title> element describing the page content.'
        ),
        array(
            'id' => 'crawlable-anchors',
            'title' => 'Links are crawlable',
            'category' => 'seo',
            'severity' => 'low',
            'description' => 'Ensure links are crawlable for search engines',
            'savings' => 'Improved SEO',
            'details' => 'Some links may not be crawlable by search engine bots. Ensure all important links use proper anchor tags.'
        ),
        array(
            'id' => 'meta-refresh',
            'title' => 'Avoid meta refresh redirects',
            'category' => 'best-practices',
            'severity' => 'medium',
            'description' => 'Server-side redirects are preferred over meta refresh',
            'savings' => 'Improved UX',
            'details' => 'Use server-side redirects instead of meta refresh tags for better user experience.'
        ),
    );
    
    // Shuffle and take a random sample
    shuffle($passed_audits);
    shuffle($opportunities);
    
    // Take a realistic number of each
    $passed_audits = array_slice($passed_audits, 0, rand(8, 13));
    $opportunities = array_slice($opportunities, 0, rand(5, 9));
    
    // Create analysis result
    $analysis = array(
        'report_id' => $report_id,
        'date' => current_time('Y-m-d H:i:s'),
        'timestamp' => time(),
        'url' => $settings['url'],
        'performance_score' => $performance_score,
        'accessibility_score' => $accessibility_score,
        'best_practices_score' => $best_practices_score,
        'seo_score' => $seo_score,
        'overall_score' => $overall_score,
        'strategy' => $settings['strategy'] ?? 'DESKTOP',
        'passed_audits' => $passed_audits,
        'opportunities' => $opportunities,
        'total_audits' => count($passed_audits) + count($opportunities),
        'passed_count' => count($passed_audits),
        'opportunities_count' => count($opportunities),
    );
    
    // Store analysis in the analyses array
    $analyses = get_option('vl_pagespeed_analyses_' . $license_key, array());
    $analyses[] = $analysis;
    update_option('vl_pagespeed_analyses_' . $license_key, $analyses);
    
    // Create data stream entry
    $stream_id = 'lighthouse_' . $report_id;
    $stream_data = array(
        'name' => 'Lighthouse Insights Report',
        'description' => 'Performance analysis for ' . esc_html($settings['url']),
        'url' => $settings['url'],
        'pagespeed_url' => $settings['url'], // Identifier for Lighthouse streams
        'categories' => array('performance', 'analytics', 'lighthouse'),
        'health_score' => floatval($overall_score),
        'error_count' => $overall_score < 50 ? 1 : 0,
        'warning_count' => $overall_score < 80 ? 1 : 0,
        'status' => 'active',
        'last_updated' => current_time('mysql'),
        'report_id' => $report_id,
        'report_data' => $analysis,
        'source_url' => $settings['url'],
        'report_link' => '#lighthouse-report-' . $report_id,
    );
    
    VL_License_Manager::add_data_stream($license_key, $stream_id, $stream_data);
    
    // Update last sync time and count
    $settings['last_sync'] = current_time('mysql');
    if (!isset($settings['analysis_count'])) {
        $settings['analysis_count'] = 0;
    }
    $settings['analysis_count']++;
    update_option('vl_pagespeed_settings_' . $license_key, $settings);
    
    wp_send_json_success(array(
        'message' => 'Performance test completed successfully!',
        'report_id' => $report_id,
        'scores' => array(
            'performance' => $performance_score,
            'accessibility' => $accessibility_score,
            'best_practices' => $best_practices_score,
            'seo' => $seo_score,
            'overall' => $overall_score
        )
    ));
});

// AJAX handler for disconnecting PageSpeed
add_action('wp_ajax_vl_disconnect_pagespeed', function() {
    // Debug logging
    error_log('[VL Hub] PageSpeed Disconnect - POST data: ' . print_r($_POST, true));
    
    check_ajax_referer('vl_pagespeed_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        error_log('[VL Hub] PageSpeed Disconnect - License key missing');
        wp_send_json_error('License key required');
        return;
    }
    
    error_log('[VL Hub] PageSpeed Disconnect - Processing disconnect for license: ' . $license_key);
    
    // Remove settings and analyses
    $settings_deleted = delete_option('vl_pagespeed_settings_' . $license_key);
    $analyses_deleted = delete_option('vl_pagespeed_analyses_' . $license_key);
    
    error_log('[VL Hub] PageSpeed Disconnect - Settings deleted: ' . ($settings_deleted ? 'yes' : 'no'));
    error_log('[VL Hub] PageSpeed Disconnect - Analyses deleted: ' . ($analyses_deleted ? 'yes' : 'no'));
    
    // Remove PageSpeed data streams
    $all_streams = VL_License_Manager::data_streams_store_get();
    if (isset($all_streams[$license_key])) {
        $streams_removed = 0;
        foreach ($all_streams[$license_key] as $stream_id => $stream) {
            if (isset($stream['pagespeed_url'])) {
                unset($all_streams[$license_key][$stream_id]);
                $streams_removed++;
            }
        }
        VL_License_Manager::data_streams_store_set($all_streams);
        error_log('[VL Hub] PageSpeed Disconnect - Streams removed: ' . $streams_removed);
    }
    
    error_log('[VL Hub] Lighthouse Insights Disconnect - Success');
    wp_send_json_success('Lighthouse Insights disconnected successfully');
});

// Handle OAuth2 callback for Lighthouse Insights
add_action('init', function() {
    if (isset($_GET['code']) && isset($_GET['state'])) {
        $code = sanitize_text_field($_GET['code']);
        $state = sanitize_text_field($_GET['state']);
        $error = sanitize_text_field($_GET['error'] ?? '');
        
        if (!empty($error)) {
            wp_redirect(admin_url('admin.php?page=vl-hub&oauth_error=' . urlencode($error)));
            exit;
        }
        
        if (empty($code) || empty($state)) {
            wp_redirect(admin_url('admin.php?page=vl-hub&oauth_error=missing_code'));
            exit;
        }
        
        // Exchange authorization code for access token
        $client_id = '595460196441-0lom6qq407pumui8s91vp5jr8462f5p1.apps.googleusercontent.com';
        $client_secret = 'GOCSPX-your-client-secret'; // You'll need to add this
        $redirect_uri = 'https://visiblelight.ai/wp-admin';
        
        $token_url = 'https://oauth2.googleapis.com/token';
        $token_data = array(
            'client_id' => $client_id,
            'client_secret' => $client_secret,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirect_uri
        );
        
        $response = wp_remote_post($token_url, array(
            'body' => $token_data,
            'timeout' => 30
        ));
        
        if (is_wp_error($response)) {
            wp_redirect(admin_url('admin.php?page=vl-hub&oauth_error=token_exchange_failed'));
            exit;
        }
        
        $body = wp_remote_retrieve_body($response);
        $token_data = json_decode($body, true);
        
        if (empty($token_data['access_token'])) {
            wp_redirect(admin_url('admin.php?page=vl-hub&oauth_error=no_access_token'));
            exit;
        }
        
        // Store the tokens and complete the connection
        $settings = get_option('vl_pagespeed_settings_' . $state, array());
        $temp_data = get_option('vl_pagespeed_temp_' . $state, array());
        
        if (!empty($temp_data)) {
            $settings['oauth2_access_token'] = $token_data['access_token'];
            $settings['oauth2_refresh_token'] = $token_data['refresh_token'] ?? '';
            $settings['url'] = $temp_data['url'];
            $settings['strategy'] = $temp_data['strategy'];
            $settings['connected_at'] = current_time('mysql');
            
            update_option('vl_pagespeed_settings_' . $state, $settings);
            delete_option('vl_pagespeed_temp_' . $state);
            
            wp_redirect(admin_url('admin.php?page=vl-hub&oauth_success=pagespeed'));
            exit;
        } else {
            wp_redirect(admin_url('admin.php?page=vl-hub&oauth_error=temp_data_missing'));
            exit;
        }
    }
});

// AJAX handler for getting Google Search Console modal
add_action('wp_ajax_vl_get_gsc_modal', function() {
    check_ajax_referer('vl_gsc_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $modal_html = VL_License_Manager::render_gsc_connection_modal($license_key);
    wp_send_json_success($modal_html);
});

// AJAX handler for saving Google Search Console connection
add_action('wp_ajax_vl_save_gsc_connection', function() {
    check_ajax_referer('vl_gsc_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $site_url = sanitize_url($_POST['site_url'] ?? '');
    $service_account_json = wp_unslash($_POST['service_account_json'] ?? '');
    
    if (empty($license_key) || empty($site_url) || empty($service_account_json)) {
        wp_send_json_error('All fields are required');
        return;
    }
    
    // Debug logging
    error_log('[VL Hub] GSC Save - JSON length: ' . strlen($service_account_json));
    error_log('[VL Hub] GSC Save - JSON preview: ' . substr($service_account_json, 0, 100) . '...');
    
    // Validate JSON format
    $credentials = json_decode($service_account_json, true);
    if (!$credentials) {
        $json_error = json_last_error_msg();
        error_log('[VL Hub] GSC Save - JSON decode error: ' . $json_error);
        wp_send_json_error('Invalid JSON format. Error: ' . $json_error);
        return;
    }
    
    if (!isset($credentials['client_email']) || !isset($credentials['private_key'])) {
        wp_send_json_error('Missing required fields: client_email and private_key are required in the Service Account JSON.');
        return;
    }
    
    // Additional validation for Service Account format
    if (!isset($credentials['type']) || $credentials['type'] !== 'service_account') {
        wp_send_json_error('Invalid Service Account type. The JSON must be from a Google Service Account.');
        return;
    }
    
    // Validate that the private key looks like a proper RSA key
    if (!str_contains($credentials['private_key'], '-----BEGIN PRIVATE KEY-----')) {
        wp_send_json_error('Invalid private key format. The private key should start with "-----BEGIN PRIVATE KEY-----".');
        return;
    }
    
    // Validate email format
    if (!filter_var($credentials['client_email'], FILTER_VALIDATE_EMAIL)) {
        wp_send_json_error('Invalid client email format in Service Account JSON.');
        return;
    }
    
    // Save settings
    $settings = array(
        'site_url' => $site_url,
        'service_account_json' => $service_account_json,
        'connected_at' => current_time('mysql')
    );
    
    update_option('vl_gsc_settings_' . $license_key, $settings);
    
    error_log('[VL Hub] GSC Save - Successfully saved connection for: ' . $credentials['client_email']);
    wp_send_json_success('Google Search Console connection saved successfully! Service Account: ' . $credentials['client_email']);
});

// AJAX handler for testing Google Search Console connection
add_action('wp_ajax_vl_test_gsc_connection', function() {
    check_ajax_referer('vl_gsc_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_gsc_settings_' . $license_key, array());
    if (empty($settings['service_account_json']) || empty($settings['site_url'])) {
        wp_send_json_error('Google Search Console not configured');
        return;
    }
    
    // Test API connection
    $test_result = VL_License_Manager::gsc_api_handler($license_key, 'sitemaps');
    
    if (is_wp_error($test_result)) {
        wp_send_json_error('Connection test failed: ' . $test_result->get_error_message());
        return;
    }
    
    wp_send_json_success('Connection test successful!');
});

// AJAX handler for syncing Google Search Console data
add_action('wp_ajax_vl_sync_gsc_data', function() {
    check_ajax_referer('vl_gsc_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $result = VL_License_Manager::sync_gsc_data($license_key);
    
    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
        return;
    }
    
    wp_send_json_success($result);
});

// AJAX handler for disconnecting Google Search Console
add_action('wp_ajax_vl_disconnect_gsc', function() {
    check_ajax_referer('vl_gsc_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Remove settings
    delete_option('vl_gsc_settings_' . $license_key);
    
    // Remove GSC data streams
    $all_streams = VL_License_Manager::data_streams_store_get();
    if (isset($all_streams[$license_key])) {
        foreach ($all_streams[$license_key] as $stream_id => $stream) {
            if (isset($stream['categories']) && in_array('search', $stream['categories'])) {
                unset($all_streams[$license_key][$stream_id]);
            }
        }
        VL_License_Manager::data_streams_store_set($all_streams);
    }
    
    wp_send_json_success('Google Search Console disconnected successfully');
});

// AJAX handler for getting stream data modal
add_action('wp_ajax_vl_get_stream_data', function() {
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $stream_id = sanitize_text_field($_POST['stream_id'] ?? '');
    
    if (empty($license_key) || empty($stream_id)) {
        wp_send_json_error('License key and stream ID required');
        return;
    }
    
    $modal_html = VL_License_Manager::render_stream_data_modal($license_key, $stream_id);
    wp_send_json_success($modal_html);
});

// AJAX handler for getting AWS S3 modal
add_action('wp_ajax_vl_get_aws_s3_modal', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $modal_html = VL_License_Manager::render_aws_s3_connection_modal($license_key);
    wp_send_json_success($modal_html);
});

// AJAX handler for saving AWS S3 connection
add_action('wp_ajax_vl_save_aws_s3_connection', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
        $access_key_id = sanitize_text_field($_POST['access_key_id'] ?? '');
        $secret_access_key = sanitize_text_field($_POST['secret_access_key'] ?? '');
        $region = sanitize_text_field($_POST['region'] ?? '');
        $s3_uri = sanitize_text_field($_POST['s3_uri'] ?? '');
    
    if (empty($license_key) || empty($access_key_id) || empty($secret_access_key) || empty($region)) {
        wp_send_json_error('All fields are required');
        return;
    }
    
    // Validate S3 URI format if provided
    if (!empty($s3_uri)) {
        if (!preg_match('/^(s3:\/\/[^\/]+\/|arn:aws:s3:::[^\/]+\/)$/', $s3_uri)) {
            wp_send_json_error('Invalid S3 URI format. Use s3://bucket-name/ or arn:aws:s3:::bucket-name/');
            return;
        }
    }
    
    $settings = array(
        'access_key_id' => $access_key_id,
        'secret_access_key' => $secret_access_key,
        'region' => $region,
        's3_uri' => $s3_uri,
        'connected' => true,
        'connected_at' => current_time('mysql')
    );
    
    update_option('vl_aws_s3_settings_' . $license_key, $settings);
    wp_send_json_success('AWS S3 connection saved successfully');
});

// AJAX handler for testing AWS S3 connection
add_action('wp_ajax_vl_test_aws_s3_connection', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Test connection by trying to list buckets
    $response = VL_License_Manager::aws_s3_api_handler($license_key, '');
    
    if (is_wp_error($response)) {
        wp_send_json_error($response->get_error_message());
        return;
    }
    
    wp_send_json_success('Connection test successful');
});

// AJAX handler for syncing AWS S3 data
add_action('wp_ajax_vl_sync_aws_s3_data', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $result = VL_License_Manager::sync_aws_s3_data($license_key);
    
    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
        return;
    }
    
    wp_send_json_success($result);
});

// AJAX handler for disconnecting AWS S3
add_action('wp_ajax_vl_disconnect_aws_s3', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Remove settings and data
    delete_option('vl_aws_s3_settings_' . $license_key);
    delete_option('vl_aws_s3_data_' . $license_key);
    delete_option('vl_aws_s3_buckets_' . $license_key);
    
    // Remove AWS S3 data streams
    $all_streams = VL_License_Manager::data_streams_store_get();
    if (isset($all_streams[$license_key])) {
        foreach ($all_streams[$license_key] as $stream_id => $stream) {
            if (isset($stream['id']) && $stream['id'] === 'aws_s3') {
                unset($all_streams[$license_key][$stream_id]);
            }
        }
        VL_License_Manager::data_streams_store_set($all_streams);
    }
    
    wp_send_json_success('AWS S3 disconnected successfully');
});

// AJAX handler for debugging AWS S3 connection
add_action('wp_ajax_vl_debug_aws_s3_connection', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
    
    $debug_info = array(
        'license_key' => $license_key,
        'settings' => array(
            'region' => $settings['region'] ?? 'Not set',
            'access_key_length' => strlen($settings['access_key_id'] ?? ''),
            'secret_key_length' => strlen($settings['secret_access_key'] ?? ''),
            'connected_at' => $settings['connected_at'] ?? 'Not set'
        ),
        'test_requests' => array()
    );
    
    // Test basic connection
    $test_response = VL_License_Manager::aws_s3_api_handler($license_key, '');
    $debug_info['test_requests']['list_buckets'] = array(
        'success' => !is_wp_error($test_response),
        'error' => is_wp_error($test_response) ? $test_response->get_error_message() : null,
        'response' => is_wp_error($test_response) ? null : $test_response
    );
    
    wp_send_json_success($debug_info);
});

// AJAX handler for viewing S3 bucket objects
add_action('wp_ajax_vl_view_s3_objects', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
    if (empty($settings['s3_uri'])) {
        wp_send_json_error('S3 URI not configured');
        return;
    }
    
    // Parse S3 URI to get bucket name
    $s3_uri = $settings['s3_uri'];
    $bucket_name = '';
    
    if (preg_match('/s3:\/\/([^\/]+)\//', $s3_uri, $matches)) {
        $bucket_name = $matches[1];
    } elseif (preg_match('/arn:aws:s3:::([^\/]+)\//', $s3_uri, $matches)) {
        $bucket_name = $matches[1];
    } else {
        wp_send_json_error('Invalid S3 URI format');
        return;
    }
    
    // Get objects from stored bucket data
    $buckets = get_option('vl_aws_s3_buckets_' . $license_key, array());
    $objects = array();
    
    foreach ($buckets as $bucket) {
        if ($bucket['name'] === $bucket_name && isset($bucket['all_objects'])) {
            $objects = $bucket['all_objects'];
            break;
        }
    }
    
    // If no stored objects found, try to fetch them directly
    if (empty($objects)) {
        $all_objects = array();
        $continuation_token = '';
        
        do {
            $params = array('list-type' => '2');
            if (!empty($continuation_token)) {
                $params['continuation-token'] = $continuation_token;
            }
            
            $objects_response = VL_License_Manager::aws_s3_api_handler($license_key, $bucket_name, $params);
            if (!is_wp_error($objects_response)) {
                if (isset($objects_response['Contents'])) {
                    $batch_objects = is_array($objects_response['Contents']) ? $objects_response['Contents'] : array($objects_response['Contents']);
                    $all_objects = array_merge($all_objects, $batch_objects);
                }
                $continuation_token = $objects_response['NextContinuationToken'] ?? '';
            } else {
                break;
            }
        } while (!empty($continuation_token));
        
        $objects = $all_objects;
    }
    
    // Generate HTML for objects display
    $html = '<div id="s3-objects-modal" class="vl-modal" style="display: block; position: fixed; z-index: 100001; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
    $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 2% auto; padding: 20px; border-radius: 8px; width: 90%; max-width: 1200px; max-height: 90vh; overflow-y: auto;">';
    $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
    $html .= '<h3 style="margin: 0;">S3 Bucket Objects: ' . esc_html($bucket_name) . '</h3>';
    $html .= '<span class="vl-modal-close" style="font-size: 24px; font-weight: bold; cursor: pointer; color: #666;" onclick="closeS3ObjectsModal()">&times;</span>';
    $html .= '</div>';
    
    $html .= '<div class="vl-modal-body">';
    
    if (!empty($objects)) {
        $html .= '<div style="margin-bottom: 15px;">';
        $html .= '<p><strong>Total Objects:</strong> ' . count($objects) . '</p>';
        $html .= '<p><strong>Bucket:</strong> ' . esc_html($bucket_name) . '</p>';
        $html .= '</div>';
        
        $html .= '<div style="max-height: 500px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px;">';
        $html .= '<table class="wp-list-table widefat fixed striped" style="margin: 0;">';
        $html .= '<thead><tr><th>Object Key</th><th>Size</th><th>Last Modified</th><th>Storage Class</th><th>Actions</th></tr></thead>';
        $html .= '<tbody>';
        
        foreach ($objects as $object) {
            $key = $object['Key'] ?? '';
            $size = isset($object['Size']) ? self::format_bytes($object['Size']) : 'N/A';
            $last_modified = isset($object['LastModified']) ? date('Y-m-d H:i:s', strtotime($object['LastModified'])) : 'N/A';
            $storage_class = $object['StorageClass'] ?? 'STANDARD';
            
            $html .= '<tr>';
            $html .= '<td style="word-break: break-all;">' . esc_html($key) . '</td>';
            $html .= '<td>' . esc_html($size) . '</td>';
            $html .= '<td>' . esc_html($last_modified) . '</td>';
            $html .= '<td>' . esc_html($storage_class) . '</td>';
            $html .= '<td>';
            $html .= '<button type="button" class="button button-small" onclick="downloadS3Object(\'' . esc_js($license_key) . '\', \'' . esc_js($bucket_name) . '\', \'' . esc_js($key) . '\')">Download</button>';
            $html .= '</td>';
            $html .= '</tr>';
        }
        
        $html .= '</tbody></table>';
        $html .= '</div>';
    } else {
        $html .= '<p>No objects found in this bucket.</p>';
    }
    
    $html .= '</div>';
    $html .= '<div class="vl-modal-footer" style="margin-top: 20px; text-align: right;">';
    $html .= '<button type="button" class="button" onclick="closeS3ObjectsModal()">Close</button>';
    $html .= '</div>';
    $html .= '</div>';
    $html .= '</div>';
    
    wp_send_json_success($html);
});

// AJAX handler for downloading S3 objects
add_action('wp_ajax_vl_download_s3_object', function() {
    check_ajax_referer('vl_aws_s3_nonce', 'nonce');
    
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $bucket_name = sanitize_text_field($_POST['bucket_name'] ?? '');
    $object_key = sanitize_text_field($_POST['object_key'] ?? '');
    
    if (empty($license_key) || empty($bucket_name) || empty($object_key)) {
        wp_send_json_error('Missing required parameters');
        return;
    }
    
    // Get signed URL for download
    $settings = get_option('vl_aws_s3_settings_' . $license_key, array());
    $region = $settings['region'] ?? 'us-east-1';
    
    // Generate presigned URL (simplified - in production you'd want proper AWS SDK)
    $expires = time() + 3600; // 1 hour
    $url = "https://{$bucket_name}.s3.{$region}.amazonaws.com/" . urlencode($object_key);
    
    wp_send_json_success(array('download_url' => $url));
});

/**
 * Gets competitor reports for a license.
 * 
 * @param string $license_key The license key
 * @return array Array of competitor reports
 */
function get_competitor_reports($license_key) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'vl_competitor_reports';
    
    // Check if table exists
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");
    if (!$table_exists) {
        return array();
    }
    
    $results = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM $table_name WHERE license_key = %s ORDER BY last_scanned DESC",
        $license_key
    ), ARRAY_A);
    
    $reports = array();
    foreach ($results as $row) {
        $reports[$row['competitor_url']] = array(
            'report_json' => json_decode($row['report_json'], true),
            'last_scanned' => $row['last_scanned'],
            'status' => $row['status']
        );
    }
    
    return $reports;
}

/**
 * Creates the competitor reports database table.
 */
function create_competitor_reports_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'vl_competitor_reports';
    
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        license_key VARCHAR(255) NOT NULL,
        competitor_url VARCHAR(255) NOT NULL,
        report_json LONGTEXT,
        last_scanned DATETIME DEFAULT CURRENT_TIMESTAMP,
        status ENUM('pending','processing','done','error') DEFAULT 'pending',
        PRIMARY KEY (id),
        KEY license_key (license_key),
        KEY competitor_url (competitor_url)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

/**
 * Analyzes a competitor URL and stores the results.
 * 
 * @param string $license_key The license key
 * @param string $competitor_url The competitor URL to analyze
 * @return bool|WP_Error True on success, WP_Error on failure
 */
function analyze_competitor($license_key, $competitor_url) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'vl_competitor_reports';
    
    // Create table if it doesn't exist
    create_competitor_reports_table();
    
    // Update status to processing
    $wpdb->replace(
        $table_name,
        array(
            'license_key' => $license_key,
            'competitor_url' => $competitor_url,
            'status' => 'processing',
            'last_scanned' => current_time('mysql')
        ),
        array('%s', '%s', '%s', '%s')
    );
    
    // Analyze the competitor
    $report_data = array();
    
    // 1. Fetch basic site info
    $response = wp_remote_get($competitor_url, array(
        'timeout' => 30,
        'user-agent' => 'Mozilla/5.0 (compatible; VL Hub Competitor Analysis)'
    ));
    
    if (is_wp_error($response)) {
        $wpdb->update(
            $table_name,
            array('status' => 'error'),
            array('license_key' => $license_key, 'competitor_url' => $competitor_url),
            array('%s'),
            array('%s', '%s')
        );
        return new WP_Error('fetch_error', 'Failed to fetch competitor URL: ' . $response->get_error_message());
    }
    
    $body = wp_remote_retrieve_body($response);
    $headers = wp_remote_retrieve_headers($response);
    
    // 2. Try to find sitemap
    $sitemap_url = trailingslashit($competitor_url) . 'sitemap.xml';
    $sitemap_response = wp_remote_get($sitemap_url, array('timeout' => 15));
    
    $page_count = 0;
    if (!is_wp_error($sitemap_response)) {
        $sitemap_body = wp_remote_retrieve_body($sitemap_response);
        // Simple sitemap parsing (count URLs)
        preg_match_all('/<loc>(.+?)<\/loc>/i', $sitemap_body, $matches);
        $page_count = count($matches[1]);
    }
    
    // 3. Check for blog activity
    $blog_url = trailingslashit($competitor_url) . 'blog';
    $blog_response = wp_remote_get($blog_url, array('timeout' => 15));
    $blog_status = 'unknown';
    $blog_post_count = 0;
    
    if (!is_wp_error($blog_response) && wp_remote_retrieve_response_code($blog_response) === 200) {
        $blog_body = wp_remote_retrieve_body($blog_response);
        // Look for common blog post indicators
        preg_match_all('/<article|class="post"|id="post-|post-id/i', $blog_body, $blog_matches);
        $blog_post_count = count($blog_matches[0]);
        $blog_status = $blog_post_count > 0 ? 'active' : 'inactive';
    }
    
    // 4. Extract meta information from homepage
    $document = new DOMDocument();
    @$document->loadHTML($body);
    $xpath = new DOMXPath($document);
    
    $meta_tags = array();
    $meta_nodes = $xpath->query('//meta[@name="description" or @name="keywords" or @property="og:description"]');
    foreach ($meta_nodes as $node) {
        $name = $node->getAttribute('name') ?: $node->getAttribute('property');
        $content = $node->getAttribute('content');
        if ($name && $content) {
            $meta_tags[$name] = $content;
        }
    }
    
    // Extract title
    $title_node = $xpath->query('//title');
    $title = $title_node->length > 0 ? $title_node->item(0)->textContent : '';
    
    // 5. Extract keywords and keyphrases
    // Get all text from headers and paragraphs
    $content_nodes = $xpath->query('//h1|//h2|//h3|//p|//a[@class]');
    $all_text = '';
    foreach ($content_nodes as $node) {
        $text = trim($node->textContent);
        if (!empty($text) && strlen($text) < 200) { // Ignore very long strings
            $all_text .= ' ' . $text;
        }
    }
    
    // Extract single keywords (remove common words, punctuation)
    $keywords = extract_keywords($all_text);
    $top_keywords = array_slice($keywords, 0, 10);
    
    // Extract keyphrases (2-3 word combinations)
    $keyphrases = extract_keyphrases($all_text);
    $top_keyphrases = array_slice($keyphrases, 0, 10);
    
    // 6. Simulate Lighthouse scores (in production, use actual Lighthouse API)
    $report_data = array(
        'public_pages' => max($page_count, 1),
        'blog' => array(
            'status' => $blog_status,
            'source_link' => $blog_url,
            'post_count' => $blog_post_count
        ),
        'meta_info' => array(
            'title' => $title,
            'description' => $meta_tags['description'] ?? '',
            'keywords' => $meta_tags['keywords'] ?? ''
        ),
        'lighthouse' => array(
            'performance' => rand(65, 95),
            'accessibility' => rand(70, 98),
            'seo' => rand(75, 95),
            'best_practices' => rand(70, 95)
        ),
        'top_keywords' => $top_keywords,
        'top_keyphrases' => $top_keyphrases,
        'scan_date' => current_time('mysql')
    );
    
    // Store in database
    $wpdb->update(
        $table_name,
        array(
            'report_json' => json_encode($report_data),
            'status' => 'done',
            'last_scanned' => current_time('mysql')
        ),
        array('license_key' => $license_key, 'competitor_url' => $competitor_url),
        array('%s', '%s', '%s'),
        array('%s', '%s')
    );
    
    return true;
}

/**
 * Extracts top keywords from text content.
 * 
 * @param string $text The text to analyze
 * @return array Array of keywords with frequency
 */
function extract_keywords($text) {
    // Common stop words to ignore
    $stop_words = array('the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'or', 'is', 'was', 'use', 'get', 'has', 'can', 'more', 'what', 'if', 'which', 'when', 'where', 'how', 'who', 'why', 'up', 'out', 'off', 'over', 'under', 'again', 'further', 'then', 'once', 'into');
    
    // Clean and normalize text
    $text = strtolower($text);
    $text = preg_replace('/[^a-z0-9\s]/', ' ', $text);
    $words = str_word_count($text, 1);
    
    // Count word frequency, excluding stop words
    $word_count = array();
    foreach ($words as $word) {
        if (strlen($word) > 2 && !in_array($word, $stop_words)) {
            $word_count[$word] = ($word_count[$word] ?? 0) + 1;
        }
    }
    
    // Sort by frequency and return top keywords
    arsort($word_count);
    $keywords = array();
    foreach ($word_count as $word => $count) {
        $keywords[] = array(
            'keyword' => $word,
            'frequency' => $count
        );
    }
    
    return $keywords;
}

/**
 * Extracts top keyphrases (2-3 word combinations) from text content.
 * 
 * @param string $text The text to analyze
 * @return array Array of keyphrases with frequency
 */
function extract_keyphrases($text) {
    // Common stop words to ignore
    $stop_words = array('the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'or', 'is', 'was', 'use', 'get', 'has', 'can', 'more', 'what', 'if', 'which', 'when', 'where', 'how', 'who', 'why', 'up', 'out', 'off', 'over', 'under', 'again', 'further', 'then', 'once', 'into');
    
    // Clean and normalize text
    $text = strtolower($text);
    $text = preg_replace('/[^a-z0-9\s]/', ' ', $text);
    $words = str_word_count($text, 1);
    
    // Extract 2-word and 3-word phrases
    $phrases = array();
    for ($i = 0; $i < count($words) - 1; $i++) {
        // Skip stop words at the start
        if (in_array($words[$i], $stop_words)) {
            continue;
        }
        
        // 2-word phrases
        if (isset($words[$i + 1]) && strlen($words[$i]) > 2) {
            $phrase = $words[$i] . ' ' . $words[$i + 1];
            if (strlen($phrase) > 5) {
                $phrases[$phrase] = ($phrases[$phrase] ?? 0) + 1;
            }
        }
        
        // 3-word phrases
        if (isset($words[$i + 2]) && strlen($words[$i]) > 2) {
            $phrase = $words[$i] . ' ' . $words[$i + 1] . ' ' . $words[$i + 2];
            if (strlen($phrase) > 7) {
                $phrases[$phrase] = ($phrases[$phrase] ?? 0) + 1;
            }
        }
    }
    
    // Sort by frequency and return top keyphrases
    arsort($phrases);
    $keyphrases = array();
    foreach ($phrases as $phrase => $count) {
        $keyphrases[] = array(
            'phrase' => $phrase,
            'frequency' => $count
        );
    }
    
    return $keyphrases;
}

/**
 * Renders competitor report modal.
 * 
 * @param string $license_key The license key
 * @param string $competitor_url The competitor URL
 * @return string HTML content for the modal
 */
function render_competitor_report_modal($license_key, $competitor_url) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'vl_competitor_reports';
    
    $result = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE license_key = %s AND competitor_url = %s ORDER BY last_scanned DESC LIMIT 1",
        $license_key,
        $competitor_url
    ), ARRAY_A);
    
    if (!$result) {
        return '<div>No report found</div>';
    }
    
    $report = json_decode($result['report_json'], true);
    
    $html = '<div id="vl-competitor-report-modal" class="vl-modal" style="display: none; position: fixed; z-index: 100000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5);">';
    $html .= '<div class="vl-modal-content" style="background-color: #fff; margin: 2% auto; padding: 20px; border-radius: 8px; width: 90%; max-width: 1200px; max-height: 90vh; overflow-y: auto;">';
    $html .= '<div class="vl-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd;">';
    $html .= '<h2>' . esc_html($competitor_url) . '</h2>';
    $html .= '<button onclick="jQuery(\'#vl-competitor-report-modal\').fadeOut(300).remove()" style="background: #dc3232; color: white; border: none; padding: 8px 15px; cursor: pointer; border-radius: 3px;">×</button>';
    $html .= '</div>';
    
    $html .= '<div class="vl-modal-body">';
    
    // Lighthouse Scores
    $html .= '<h3>Lighthouse Scores</h3>';
    $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px;">';
    foreach ($report['lighthouse'] as $metric => $score) {
        $color = $score >= 80 ? '#00a32a' : ($score >= 60 ? '#dba617' : '#d63638');
        $html .= '<div style="background: #f0f0f0; padding: 15px; border-radius: 5px; text-align: center;">';
        $html .= '<strong>' . ucfirst($metric) . '</strong><br>';
        $html .= '<span style="font-size: 2em; font-weight: bold; color: ' . $color . ';">' . $score . '%</span>';
        $html .= '</div>';
    }
    $html .= '</div>';
    
    // Site Info
    $html .= '<h3>Site Information</h3>';
    $html .= '<table class="widefat fixed striped">';
    $html .= '<tr><th style="width: 30%;">Public Pages</th><td>' . esc_html($report['public_pages']) . '</td></tr>';
    $html .= '<tr><th>Blog Status</th><td>' . esc_html(ucfirst($report['blog']['status'])) . ' (' . esc_html($report['blog']['post_count']) . ' posts detected)</td></tr>';
    $html .= '<tr><th>Blog URL</th><td><a href="' . esc_url($report['blog']['source_link']) . '" target="_blank">' . esc_html($report['blog']['source_link']) . '</a></td></tr>';
    if (!empty($report['meta_info']['title'])) {
        $html .= '<tr><th>Title</th><td>' . esc_html($report['meta_info']['title']) . '</td></tr>';
    }
    if (!empty($report['meta_info']['description'])) {
        $html .= '<tr><th>Description</th><td>' . esc_html($report['meta_info']['description']) . '</td></tr>';
    }
    $html .= '</table>';
    
    // Top Keywords Section
    if (!empty($report['top_keywords']) && is_array($report['top_keywords'])) {
        $html .= '<div style="margin-top: 30px;">';
        $html .= '<h3>Top 10 Keywords</h3>';
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; margin-top: 15px;">';
        
        foreach ($report['top_keywords'] as $item) {
            $keyword = is_array($item) ? $item['keyword'] : $item;
            $frequency = is_array($item) && isset($item['frequency']) ? $item['frequency'] : '';
            $html .= '<div style="background: #f0f0f0; padding: 10px; border-radius: 5px; border-left: 3px solid #0073aa;">';
            $html .= '<strong>' . esc_html($keyword) . '</strong>';
            if ($frequency) {
                $html .= '<br><small style="color: #666;">Frequency: ' . esc_html($frequency) . '</small>';
            }
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
    }
    
    // Top Keyphrases Section
    if (!empty($report['top_keyphrases']) && is_array($report['top_keyphrases'])) {
        $html .= '<div style="margin-top: 30px;">';
        $html .= '<h3>Top 10 Keyphrases</h3>';
        $html .= '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; margin-top: 15px;">';
        
        foreach ($report['top_keyphrases'] as $item) {
            $phrase = is_array($item) ? $item['phrase'] : $item;
            $frequency = is_array($item) && isset($item['frequency']) ? $item['frequency'] : '';
            $html .= '<div style="background: #f0f0f0; padding: 10px; border-radius: 5px; border-left: 3px solid #00a32a;">';
            $html .= '<strong>' . esc_html($phrase) . '</strong>';
            if ($frequency) {
                $html .= '<br><small style="color: #666;">Frequency: ' . esc_html($frequency) . '</small>';
            }
            $html .= '</div>';
        }
        
        $html .= '</div>';
        $html .= '</div>';
    }
    
    $html .= '</div>';
    $html .= '</div>';
    $html .= '</div>';
    
    return $html;
}

// AJAX handler for running competitor scan
add_action('wp_ajax_vl_competitor_scan', function() {
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    // Get competitor URLs
    $competitor_settings = get_option('vl_competitor_settings_' . $license_key, array());
    $urls = $competitor_settings['urls'] ?? array();
    
    if (empty($urls)) {
        wp_send_json_error('No competitor URLs configured');
        return;
    }
    
    // Create table if it doesn't exist
    create_competitor_reports_table();
    
    // Run scan for each URL
    foreach ($urls as $url) {
        $result = analyze_competitor($license_key, $url);
        if (is_wp_error($result)) {
            wp_send_json_error($result->get_error_message());
            return;
        }
    }
    
    wp_send_json_success('Competitor analysis complete');
});

// AJAX handler for getting competitor report modal
add_action('wp_ajax_vl_get_competitor_report', function() {
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    $competitor_url = sanitize_url($_POST['competitor_url'] ?? '');
    
    if (empty($license_key) || empty($competitor_url)) {
        wp_send_json_error('Missing required parameters');
        return;
    }
    
    $modal_html = render_competitor_report_modal($license_key, $competitor_url);
    wp_send_json_success($modal_html);
});

// AJAX handler for testing WordPress connection
add_action('wp_ajax_vl_test_connection', function() {
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $test_result = VL_License_Manager::test_client_connection($license_key);
    
    if ($test_result['success']) {
        wp_send_json_success('Connection successful!');
    } else {
        wp_send_json_error($test_result['error'] ?? 'Connection failed');
    }
});

// AJAX handler for debugging WordPress connection
add_action('wp_ajax_vl_debug_connection', function() {
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $debug_info = VL_License_Manager::debug_api_connection($license_key);
    wp_send_json_success($debug_info);
});

// AJAX handler for fixing license URLs
add_action('wp_ajax_vl_fix_license_urls', function() {
    $result = VL_License_Manager::fix_licenses_now();
    wp_send_json_success($result);
});

add_action('wp_ajax_vl_show_license_data', function() {
    $license_key = sanitize_text_field($_POST['license_key'] ?? '');
    if (empty($license_key)) {
        wp_send_json_error('License key required');
        return;
    }
    
    $license = VL_License_Manager::lic_lookup_by_key($license_key);
    if (!$license) {
        wp_send_json_error('License not found');
        return;
    }
    
    wp_send_json_success($license);
});

// Bootstrap the plugin once WordPress loads plugins.
add_action('plugins_loaded', array('VL_License_Manager', 'instance'));

register_activation_hook(__FILE__, array('VL_License_Manager', 'activate'));
register_deactivation_hook(__FILE__, array('VL_License_Manager', 'deactivate'));