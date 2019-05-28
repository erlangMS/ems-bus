-module(ems_bus_app).

-behaviour(application).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").


%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================


start(_StartType, StartArgs) ->
	io:format("\n"),
	ems_logger:format_info("Loading ~s instance ( \033[0;32mPID:\033[0m \033[01;34m~s\033[0m  \033[0;32mErlang/OTP Version:\033[0m \033[01;34m~s\033[0m )", [?SERVER_NAME, os:getpid(), erlang:system_info(otp_release)]),
	ems_db:start(),
	case ems_config:start() of
		{ok, _Pid} ->
			Conf = ems_config:getConfig(),
			ems_logger:set_level(info),
			ems_dispatcher:start(),
			Ret = ems_bus_sup:start_link(StartArgs),
			AuthorizationMode = case Conf#config.authorization of
									basic -> <<"basic, oauth2">>;
									oauth2 -> <<"oauth2">>;
									public -> <<"public">>
								end,
			ems_logger:info("Parameters:"),
			ems_logger:info("  \033[0;32mconfig_file\033[0m: \033[01;34m~p\033[0m.", [Conf#config.config_file]),
			ems_logger:info("  \033[0;32mhost_search\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_host_search]),
			ems_logger:info("  \033[0;32mnode_search\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_node_search]),
			ems_logger:info("  \033[0;32mhostname\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ems_hostname]),
			ems_logger:info("  \033[0;32mrest_base_url\033[0m: \033[01;34m~p\033[0m.", [Conf#config.rest_base_url]),
			ems_logger:info("  \033[0;32mrest_auth_url\033[0m: \033[01;34m~p\033[0m.", [Conf#config.rest_auth_url]),
			ems_logger:info("  \033[0;32mrest_login_url\033[0m: \033[01;34m~p\033[0m.", [Conf#config.rest_login_url]),
			case Conf#config.oauth2_with_check_constraint of
				true -> ems_logger:info("  \033[0;32mrest_authorization\033[0m: \033[01;34m~p\033[0m <<with check constraint>>.", [AuthorizationMode]);
				false -> ems_logger:info("  \033[0;32mrest_authorization\033[0m: \033[01;34m~p\033[0m.", [AuthorizationMode])
			end,
			ems_logger:info("  \033[0;32mrest_environment\033[0m: \033[01;34m~p\033[0m.", [Conf#config.rest_environment]),
			ems_logger:info("  \033[0;32mrest_default_querystring\033[0m: \033[01;34m~p\033[0m.", [Conf#config.rest_default_querystring]),
			ems_logger:info("  \033[0;32mrestricted_services_owner\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_restricted_services_owner]),
			ems_logger:info("  \033[0;32mrestricted_services_admin\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_restricted_services_admin]),
			ems_logger:info("  \033[0;32moauth2_refresh_token\033[0m: \033[01;34m~p\033[0m.", [Conf#config.oauth2_refresh_token]),
			ems_logger:info("  \033[0;32mauth_allow_user_inative_credentials\033[0m: \033[01;34m~p\033[0m.", [Conf#config.auth_allow_user_inative_credentials]),
			ems_logger:info("  \033[0;32mtcp_listen_address\033[0m: \033[01;34m~p\033[0m.", [Conf#config.tcp_listen_address]),
			ems_logger:info("  \033[0;32mtcp_allowed_address\033[0m: \033[01;34m~p\033[0m.", [Conf#config.tcp_allowed_address]),
			ems_logger:info("  \033[0;32mtcp_listen_prefix_interface_names\033[0m: \033[01;34m~p\033[0m.", [Conf#config.tcp_listen_prefix_interface_names]),
			ems_logger:info("  \033[0;32mlog_show_response\033[0m: \033[01;34m~p\033[0m.", [Conf#config.log_show_response]),
			ems_logger:info("  \033[0;32mlog_show_payload\033[0m: \033[01;34m~p\033[0m.", [Conf#config.log_show_payload]),
			ems_logger:info("  \033[0;32mlog_show_response_max_length\033[0m: \033[01;34m~p bytes\033[0m.", [Conf#config.log_show_response_max_length]),
			ems_logger:info("  \033[0;32mlog_show_payload_max_length\033[0m: \033[01;34m~p bytes\033[0m.", [Conf#config.log_show_payload_max_length]),
			ems_logger:info("  \033[0;32mlog_show_odbc_pool_activity\033[0m: \033[01;34m~p bytes\033[0m.", [Conf#config.log_show_odbc_pool_activity]),
			ems_logger:info("  \033[0;32mlog_file_checkpoint\033[0m: \033[01;34m~pms\033[0m.", [Conf#config.log_file_checkpoint]),
			ems_logger:info("  \033[0;32mlog_file_max_size\033[0m: \033[01;34m~p bytes\033[0m.", [Conf#config.log_file_max_size]),
			ems_logger:info("  \033[0;32mlog_file_path\033[0m: \033[01;34m~p\033[0m.", [Conf#config.log_file_path]),
			ems_logger:info("  \033[0;32mlog_file_archive_path\033[0m: \033[01;34m~p\033[0m.", [Conf#config.log_file_archive_path]),
			ems_logger:info("  \033[0;32mwww_path\033[0m: \033[01;34m~p\033[0m.", [maps:get(<<"www_path">>, Conf#config.static_file_path_map, <<>>)]),
			ems_logger:info("  \033[0;32mshow_debug_response_headers\033[0m: \033[01;34m~p\033[0m.", [Conf#config.show_debug_response_headers]),
			ems_logger:info("  \033[0;32mresult_cache\033[0m: \033[01;34m~pms\033[0m.", [Conf#config.ems_result_cache]),
			ems_logger:info("  \033[0;32mresult_cache_shared\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ems_result_cache_shared]),
			ems_logger:info("  \033[0;32mresult_cache_enabled\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ems_result_cache_enabled]),
			ems_logger:info("  \033[0;32mjava_home\033[0m: \033[01;34m~s\033[0m.", [Conf#config.java_home]),
			ems_logger:info("  \033[0;32mjava_jar_path\033[0m: \033[01;34m~s\033[0m.", [Conf#config.java_jar_path]),
			ems_logger:info("  \033[0;32mjava_thread_pool\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_thread_pool]),
			ems_logger:info("  \033[0;32mjava_service_scan\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_scan]),
			ems_logger:info("  \033[0;32mjava_service_user_notify\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_user_notify]),
			ems_logger:info("  \033[0;32mjava_service_user_notify_full_sync_enabled\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_user_notify_full_sync_enabled]),
			ems_logger:info("  \033[0;32mjava_service_user_notify_on_load_enabled\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_user_notify_on_load_enabled]),
			ems_logger:info("  \033[0;32mjava_service_user_notify_on_update_enabled\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_user_notify_on_update_enabled]),
			ems_logger:info("  \033[0;32mjava_service_user_notify_required_fields\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_user_notify_required_fields]),
			ems_logger:info("  \033[0;32mjava_service_user_notify_source_types\033[0m: \033[01;34m~p\033[0m.", [Conf#config.java_service_user_notify_source_types]),
			ems_logger:info("  \033[0;32mlog_show_user_notify_activity\033[0m: \033[01;34m~p\033[0m.", [Conf#config.log_show_user_notify_activity]),
			ems_logger:info("  \033[0;32mdisable_services\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_disable_services]),
			ems_logger:info("  \033[0;32mdisable_services_owner\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_disable_services_owner]),
			ems_logger:info("  \033[0;32menable_services\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_enable_services]),
			ems_logger:info("  \033[0;32mcatalog_path\033[0m: \033[01;34m~p\033[0m.", [Conf#config.cat_path_search]),
			ems_logger:info("  \033[0;32mdatasources\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ems_datasources]),
			ems_logger:info("  \033[0;32msufixo_email_institucional\033[0m: \033[01;34m~p\033[0m.", [Conf#config.sufixo_email_institucional]),
			ems_logger:info("  \033[0;32mstatic_file_path\033[0m: \033[01;34m~p\033[0m.", [Conf#config.static_file_path]),
			ems_logger:info("  \033[0;32mstatic_file_path_probing\033[0m: \033[01;34m~p\033[0m.", [Conf#config.static_file_path_probing]),
			ems_logger:info("  \033[0;32mhttp_max_content_length\033[0m: \033[01;34m~p bytes\033[0m.", [Conf#config.http_max_content_length]),
			ems_logger:info("  \033[0;32mhttp_headers\033[0m: \033[01;34m~p\033[0m.", [Conf#config.http_headers]),
			ems_logger:info("  \033[0;32mhttp_headers_options\033[0m: \033[01;34m~p\033[0m.", [Conf#config.http_headers_options]),
			ems_logger:info("  \033[0;32mssl_cacertfile\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ssl_cacertfile]),
			ems_logger:info("  \033[0;32mssl_certfile\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ssl_certfile]),
			ems_logger:info("  \033[0;32mssl_keyfile\033[0m: \033[01;34m~p\033[0m.", [Conf#config.ssl_keyfile]),
			ems_logger:info("  \033[0;32mcustom_variables\033[0m: \033[01;34m~p\033[0m.", [Conf#config.custom_variables]),
			Ret;
		{error, Reason} ->
			ems_logger:format_error("Error processing configuration file. Reason: ~p. Terminate...\n", [Reason]),
			erlang:halt(),
			{error, finish}
	end.

stop(_State) ->
    ems_logger:info("Stopping server...\n"),
    ems_logger:sync(),
    ems_bus_sup:stop(),
	ems_config:stop(),
    ok.
    
    
													 
    
