import setuptools

with open('VERSION.txt', 'r') as f:
    version = f.read().strip()

setuptools.setup(
    name="odoo10-addons-oca-server-tools",
    description="Meta package for oca-server-tools Odoo addons",
    version=version,
    install_requires=[
        'odoo10-addon-attachment_base_synchronize',
        'odoo10-addon-auditlog',
        'odoo10-addon-auth_admin_passkey',
        'odoo10-addon-auth_brute_force',
        'odoo10-addon-auth_oauth_multi_token',
        'odoo10-addon-auth_session_timeout',
        'odoo10-addon-auth_signup_verify_email',
        'odoo10-addon-auth_supplier',
        'odoo10-addon-auth_totp',
        'odoo10-addon-auth_totp_password_security',
        'odoo10-addon-auth_user_case_insensitive',
        'odoo10-addon-auto_backup',
        'odoo10-addon-base_cron_exclusion',
        'odoo10-addon-base_custom_info',
        'odoo10-addon-base_exception',
        'odoo10-addon-base_export_manager',
        'odoo10-addon-base_export_security',
        'odoo10-addon-base_external_dbsource',
        'odoo10-addon-base_external_dbsource_firebird',
        'odoo10-addon-base_external_dbsource_mssql',
        'odoo10-addon-base_external_dbsource_mysql',
        'odoo10-addon-base_external_dbsource_odbc',
        'odoo10-addon-base_external_dbsource_oracle',
        'odoo10-addon-base_external_dbsource_sqlite',
        'odoo10-addon-base_external_system',
        'odoo10-addon-base_fontawesome',
        'odoo10-addon-base_import_default_enable_tracking',
        'odoo10-addon-base_import_match',
        'odoo10-addon-base_import_security_group',
        'odoo10-addon-base_kanban_stage',
        'odoo10-addon-base_kanban_stage_state',
        'odoo10-addon-base_locale_uom_default',
        'odoo10-addon-base_manifest_extension',
        'odoo10-addon-base_multi_image',
        'odoo10-addon-base_optional_quick_create',
        'odoo10-addon-base_report_auto_create_qweb',
        'odoo10-addon-base_search_fuzzy',
        'odoo10-addon-base_suspend_security',
        'odoo10-addon-base_technical_features',
        'odoo10-addon-base_technical_user',
        'odoo10-addon-base_tier_validation',
        'odoo10-addon-base_user_gravatar',
        'odoo10-addon-base_user_role',
        'odoo10-addon-base_view_inheritance_extension',
        'odoo10-addon-configuration_helper',
        'odoo10-addon-database_cleanup',
        'odoo10-addon-date_range',
        'odoo10-addon-datetime_formatter',
        'odoo10-addon-dbfilter_from_header',
        'odoo10-addon-dead_mans_switch_client',
        'odoo10-addon-disable_odoo_online',
        'odoo10-addon-fetchmail_notify_error_to_sender',
        'odoo10-addon-html_image_url_extractor',
        'odoo10-addon-html_text',
        'odoo10-addon-keychain',
        'odoo10-addon-letsencrypt',
        'odoo10-addon-mail_environment',
        'odoo10-addon-mail_log_message_to_process',
        'odoo10-addon-mass_editing',
        'odoo10-addon-mass_sorting',
        'odoo10-addon-module_auto_update',
        'odoo10-addon-module_prototyper',
        'odoo10-addon-onchange_helper',
        'odoo10-addon-password_security',
        'odoo10-addon-res_config_settings_enterprise_remove',
        'odoo10-addon-scheduler_error_mailer',
        'odoo10-addon-sentry',
        'odoo10-addon-sequence_check_digit',
        'odoo10-addon-server_environment',
        'odoo10-addon-server_environment_ir_config_parameter',
        'odoo10-addon-sql_export',
        'odoo10-addon-sql_request_abstract',
        'odoo10-addon-subscription_action',
        'odoo10-addon-user_immutable',
        'odoo10-addon-user_threshold',
        'odoo10-addon-users_ldap_groups',
        'odoo10-addon-users_ldap_mail',
        'odoo10-addon-users_ldap_populate',
        'odoo10-addon-webhook',
    ],
    classifiers=[
        'Programming Language :: Python',
        'Framework :: Odoo',
    ]
)
