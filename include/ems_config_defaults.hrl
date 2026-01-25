%%********************************************************************
%% @title Default Configuration for ErlangMS
%% @version 1.0.0
%% @doc This file defines the default values used when a configuration 
%%      key is missing from emsbus.conf.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-ifndef(EMS_CONFIG_DEFAULTS_HRL).
-define(EMS_CONFIG_DEFAULTS_HRL, true).

-define(CONFIG_DEFAULTS, #{
    <<"instance_type">> => <<"production">>,
    <<"host_search">> => [<<"local">>],
    <<"node_search">> => [<<"127.0.0.1">>],
    <<"priv_path">> => <<"priv">>,
    <<"database_path">> => <<"priv/db">>,
    <<"log_file_path">> => <<"priv/log">>,
    <<"authorization">> => <<"oauth2">>,
    <<"oauth2_with_check_constraint">> => false,
    <<"oauth2_refresh_token">> => 7200,
    <<"auth_default_scope">> => [<<"user_fs">>],
    <<"debug">> => false,
    <<"sufixo_email_institucional">> => <<"@unb.br">>,
    <<"http_max_content_length">> => 524288,
    <<"log_show_response">> => false,
    <<"log_show_payload">> => false,
    <<"log_show_response_max_length">> => 120,
    <<"log_show_payload_max_length">> => 120,
    <<"log_show_content_static_file">> => false,
    <<"log_show_odbc_pool_activity">> => false,
    <<"log_show_data_loader_activity">> => true,
    <<"log_show_user_notify_activity">> => false,
    <<"rest_url_mask">> => false,
    <<"rest_use_host_in_redirect">> => true,
    <<"rest_user">> => <<"erlangms">>,
    <<"rest_passwd">> => <<"5outLag1">>,
    <<"result_cache">> => 10000,
    <<"result_cache_enabled">> => true,
    <<"tcp_listen_address">> => [<<"0.0.0.0">>],
    <<"tcp_allowed_address">> => [<<"*.*.*.*">>],
    <<"static_file_path_probing">> => false,
    <<"static_file_path">> => #{<<"www_path">> => <<"priv/www">>},
    <<"smtp_port">> => 587,
    <<"oauth2_resource_owner_find_permission_with_cpf">> => true,
    <<"oauth2_resource_owner_fields">> => ?OAUTH2_RESOURCE_OWNER_FIELDS,
    <<"custom_variables">> => #{},
    <<"hostname">> => <<>>,
    <<"tcp_listen_prefix_interface_names">> => ?TCP_LISTEN_PREFIX_INTERFACE_NAMES,
    <<"http_headers">> => #{
        <<"cache-control">> => <<"max-age=31536000, private, no-cache, no-store, must-revalidate">>,
        <<"access-control-allow-origin">> => <<"*">>,
        <<"access-control-max-age">> => <<"31536000">>,
        <<"access-control-allow-headers">> => <<"accept, accept-language, content-language, content-type, x-access_token, x-csrf-token, access-control-allow-origin, authorization, origin, x-requested-with, content-range, content-disposition, content-description">>,
        <<"access-control-allow-methods">> => <<"GET, POST, PUT, DELETE, OPTIONS, HEAD">>,
        <<"access-control-expose-headers">> => <<"cache-control, content-language, content-type, expires, last-modified, pragma, content-length">>,
        <<"x-xss-protection">> => <<"1; mode=block">>,
        <<"x-frame-options">> => <<"SAMEORIGIN">>,
        <<"x-content-type-options">> => <<"nosniff">>
    },
    <<"http_headers_options">> => #{
        <<"cache-control">> => <<"max-age=31536000, private, no-cache, no-store, must-revalidate">>,
        <<"access-control-allow-origin">> => <<"*">>,
        <<"access-control-max-age">> => <<"31536000">>,
        <<"access-control-allow-headers">> => <<"accept, accept-language, content-language, content-type, x-access_token, x-csrf-token, access-control-allow-origin, authorization, origin, x-requested-with, content-range, content-disposition, content-description">>,
        <<"access-control-allow-methods">> => <<"GET, POST, PUT, DELETE, OPTIONS, HEAD">>,
        <<"access-control-expose-headers">> => <<"cache-control, content-language, content-type, expires, last-modified, pragma, content-length">>,
        <<"x-xss-protection">> => <<"1; mode=block">>,
        <<"x-frame-options">> => <<"SAMEORIGIN">>,
        <<"x-content-type-options">> => <<"nosniff">>
    },
    <<"rest_default_querystring">> => [
        #{<<"name">> => <<"token">>, <<"type">> => <<"string">>, <<"default">> => <<>>, <<"comment">> => <<"Token OAuth2">>},
        #{<<"name">> => <<"access_token">>, <<"type">> => <<"string">>, <<"default">> => <<>>, <<"comment">> => <<"Token OAuth2">>}
    ],
    <<"catalog_path">> => #{<<"ems-bus">> => <<"priv/catalog/catalog.json">>},
    <<"rest_base_url">> => <<"http://localhost:2301/">>,
    <<"rest_auth_url">> => <<"http://localhost:2301/authorize">>,
    <<"rest_login_url">> => <<>>,
    <<"rest_environment">> => <<>>,
    <<"auth_password_check_between_scope">> => true,
    <<"disable_services">> => [],
    <<"enable_services">> => [],
    <<"disable_services_owner">> => [],
    <<"enable_services_owner">> => [],
    <<"restricted_services_owner">> => ?RESTRICTED_SERVICES_OWNER,
    <<"restricted_services_admin">> => ?RESTRICTED_SERVICES_ADMIN,
    <<"smtp_passwd">> => <<>>,
    <<"smtp_from">> => <<>>,
    <<"smtp_mail">> => <<>>,
    <<"ldap_url">> => <<>>,
    <<"ldap_admin">> => <<>>,
    <<"ldap_password_admin_crypto">> => <<>>,
    <<"ldap_base_search">> => <<>>,
    <<"ldap_password_admin">> => <<>>,
    <<"client_path_search">> => ?CLIENT_PATH_DEFAULT,
    <<"user_path_search">> => ?USER_PATH_DEFAULT,
    <<"user_dados_funcionais_path">> => ?USER_DADOS_FUNCIONAIS_PATH_DEFAULT,
    <<"user_perfil_path_search">> => ?USER_PERFIL_PATH_DEFAULT,
    <<"user_permission_path_search">> => ?USER_PERMISSION_PATH_DEFAULT,
    <<"user_endereco_path_search">> => ?USER_ENDERECO_PATH_DEFAULT,
    <<"user_telefone_path_search">> => ?USER_TELEFONE_PATH_DEFAULT,
    <<"user_email_path_search">> => ?USER_EMAIL_PATH_DEFAULT,
    <<"ssl_cacertfile">> => undefined,
    <<"ssl_certfile">> => undefined,
    <<"ssl_keyfile">> => undefined,
    <<"crypto_blowfish_module_path">> => <<>>,
    <<"user_agent_denied_list">> => [<<"sqlmap">>, <<"nikto">>, <<"nmap">>, <<"nessus">>, <<"masscan">>, <<"zgrab">>, <<"w3af">>, <<"acunetix">>, <<"havij">>, <<"dirbuster">>, <<"gobuster">>, <<"hydra">>, <<"metasploit">>, <<"netsparker">>]
}).

-endif.
