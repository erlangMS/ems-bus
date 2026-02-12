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
	ems_logger:format_info("Loading ~s ( PID: ~s  Erlang/OTP Version: ~s )", [?SERVER_NAME, os:getpid(), erlang:system_info(otp_release)]),
	case ems_config:start() of
		{ok, _Pid} ->
			Conf = ems_config:getConfig(),
			ems_cache:new(ets_result_cache_get),
			ems_cache:new(ems_user_cache),
			ems_cache:new(ems_db_parsed_query_cache),
			% Table for waiting workers for result_cache (atomic registration)
			ets:new(ets_result_cache_waiting, [duplicate_bag, named_table, public, {write_concurrency, true}]),
			ets:new(ems_dispatcher_post_time, [set, named_table, public]),
			ets:new(ctrl_node_dispatch, [set, named_table, public]),
			
			% Catalog ETS tables
			ets:new(ets_catalog_re_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_re_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_get_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_post_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_put_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_delete_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_options_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_kernel_db, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_get_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_post_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_put_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_delete_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_options_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),
			ets:new(ets_catalog_kernel_fs, [set, named_table, public, {read_concurrency, true}, {keypos, #service.rowid}]),

			Ret = ems_bus_sup:start_link(StartArgs),
			AuthorizationMode = case Conf#config.authorization of
									basic -> <<"basic, oauth2">>;
									oauth2 -> <<"oauth2">>;
									public -> <<"public">>
								end,
			ems_logger:info("Server: ~p", [?SERVER_NAME]),
			ems_logger:info("Erlang Runtime: ~p", [erlang:system_info(otp_release)]),
			ems_logger:info("ems-bus PID: ~p", [os:getpid()]),
			ems_logger:info("Parameters:"),
			ems_logger:info("  config_file: ~p.", [Conf#config.config_file]),
			ems_logger:info("  priv_path: ~p.", [Conf#config.priv_path]),
			ems_logger:info("  database_path: ~p.", [Conf#config.database_path]),
			ems_logger:info("  catalog_path: ~p.", [Conf#config.cat_path_search]),
			ems_logger:info("  custom_variables: ~p.", [Conf#config.custom_variables]),
			ems_logger:info("  static_file_path: ~p.", [Conf#config.static_file_path]),
			ems_logger:info("  static_file_path_probing: ~p.", [Conf#config.static_file_path_probing]),
			ems_logger:info("  rest_base_url: ~p.", [Conf#config.rest_base_url]),
			ems_logger:info("  rest_base_auth_url: ~p.", [Conf#config.rest_base_auth_url]),
			ems_logger:info("  rest_auth_url: ~p.", [Conf#config.rest_auth_url]),
			ems_logger:info("  rest_login_url: ~p.", [Conf#config.rest_login_url]),
			case Conf#config.oauth2_with_check_constraint of
				true -> ems_logger:info("  rest_authorization: ~p <<with check constraint>>.", [AuthorizationMode]);
				false -> ems_logger:info("  rest_authorization: ~p.", [AuthorizationMode])
			end,
			ems_logger:info("  rest_default_querystring: ~p.", [Conf#config.rest_default_querystring]),
			ems_logger:info("  rest_use_host_in_redirect: ~p.", [Conf#config.rest_use_host_in_redirect]),
			ems_logger:info("  auth_allow_user_inative_credentials: ~p.", [Conf#config.auth_allow_user_inative_credentials]),
			ems_logger:info("  auth_default_scope: ~w.", [Conf#config.auth_default_scope]),
			ems_logger:info("  auth_password_check_between_scope: ~p.", [Conf#config.auth_password_check_between_scope]),
			case ems_db:get_param(use_blowfish_crypto) of
				true -> ems_logger:info("  crypto_blowfish_module_path: ~p.", [Conf#config.crypto_blowfish_module_path]);
				false -> ok
			end,
			ems_logger:info("  restricted_services_owner: ~300p.", [Conf#config.cat_restricted_services_owner]),
			ems_logger:info("  restricted_services_admin: ~p.", [Conf#config.cat_restricted_services_admin]),
			ems_logger:info("  oauth2_refresh_token: ~p.", [Conf#config.oauth2_refresh_token]),
			ems_logger:info("  oauth2_resource_owner_find_permission_with_cpf: ~p.", [Conf#config.oauth2_resource_owner_find_permission_with_cpf]),
			ems_logger:info("  oauth2_resource_owner_fields: ~p.", [Conf#config.oauth2_resource_owner_fields]),
			ems_logger:info("  tcp_listen_address: ~300p.", [Conf#config.tcp_listen_address]),
			ems_logger:info("  tcp_allowed_address: ~300p.", [Conf#config.tcp_allowed_address]),
			ems_logger:info("  tcp_listen_prefix_interface_names: ~300p.", [Conf#config.tcp_listen_prefix_interface_names]),
			ems_logger:info("  log_show_response: ~p.", [Conf#config.log_show_response]),
			ems_logger:info("  log_show_payload: ~p.", [Conf#config.log_show_payload]),
			ems_logger:info("  log_show_content_static_file: ~p.", [Conf#config.log_show_content_static_file]),
			ems_logger:info("  log_show_response_max_length: ~p bytes (~p KB, ~p MB, ~p GB).", [Conf#config.log_show_response_max_length, round(Conf#config.log_show_response_max_length/1024), round(Conf#config.log_show_response_max_length/1048576), round(Conf#config.log_show_response_max_length/1073741824)]),
			ems_logger:info("  log_show_payload_max_length: ~p bytes (~p KB, ~p MB, ~p GB).", [Conf#config.log_show_payload_max_length, round(Conf#config.log_show_payload_max_length/1024), round(Conf#config.log_show_payload_max_length/1048576), round(Conf#config.log_show_payload_max_length/1073741824)]),
			ems_logger:info("  log_show_odbc_pool_activity: ~p.", [Conf#config.log_show_odbc_pool_activity]),
			ems_logger:info("  result_cache: ~pms.", [Conf#config.ems_result_cache]),
			ems_logger:info("  result_cache_enabled: ~p.", [Conf#config.ems_result_cache_enabled]),
			ems_logger:info("  disable_services: ~300p.", [Conf#config.cat_disable_services]),
			ems_logger:info("  disable_services_owner: ~p.", [Conf#config.cat_disable_services_owner]),
			ems_logger:info("  enable_services: ~300p.", [Conf#config.cat_enable_services]),
			ems_logger:info("  datasources: ~p.", [Conf#config.ems_datasources]),
			ems_logger:info("  cors_domain: ~p.", [ems_db:get_param(cors_domain, ?CORS_DOMAIN)]),
			ems_logger:info("  sufixo_email_institucional: ~p.", [Conf#config.sufixo_email_institucional]),
			ems_logger:info("  http_max_content_length: ~p bytes (~p KB, ~p MB, ~p GB).", [Conf#config.http_max_content_length, round(Conf#config.http_max_content_length/1024), round(Conf#config.http_max_content_length/1048576), round(Conf#config.http_max_content_length/1073741824)]),

			ems_logger:info("  ssl_cacertfile: ~p.", [Conf#config.ssl_cacertfile]),
			ems_logger:info("  ssl_certfile: ~p.", [Conf#config.ssl_certfile]),
			ems_logger:info("  ssl_keyfile: ~p.", [Conf#config.ssl_keyfile]),
			ems_logger:info("  rate_limit_cidr_interno: ~p.", [Conf#config.rate_limit_cidr_interno]),
			ems_logger:info("  rate_limit_interno: ~p req/s.", [Conf#config.rate_limit_interno]),
			ems_logger:info("  rate_limit_externo: ~p req/s.", [Conf#config.rate_limit_externo]),
			ems_logger:info("  force_https: ~p.", [Conf#config.force_https]),
			ems_logger:info("  debug: ~p.", [Conf#config.debug]),
			erlang:set_cookie(node(), erlangms), ems_logger:info("Cookie loaded: ~p", [erlang:get_cookie()]), Ret;
		{error, Reason} ->
			ems_logger:format_error("Loading failed. Reason: ~p.\n", [Reason]),
			erlang:halt(),
			{error, finish}
	end.

stop(_State) ->
    ems_logger:info("Stopping server...\n"),
    ok.
    
    
													 
    
