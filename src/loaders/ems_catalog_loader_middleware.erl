%%********************************************************************
%% @title Module ems_catalog_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load catalog services from filesystem or db
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_catalog_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, check_remove_records/2, after_load_or_update_checkpoint/1]).


-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	
	mnesia:table_info(catalog_get_db, size) == 0 andalso
	mnesia:table_info(catalog_post_db, size) == 0 andalso
	mnesia:table_info(catalog_put_db, size) == 0 andalso
	mnesia:table_info(catalog_delete_db, size) == 0 andalso
	mnesia:table_info(catalog_options_db, size) == 0 andalso
	mnesia:table_info(catalog_re_db, size) == 0 andalso
	mnesia:table_info(catalog_kernel_db, size) == 0;
is_empty(fs) ->	
	mnesia:table_info(catalog_get_fs, size) == 0 andalso
	mnesia:table_info(catalog_post_fs, size) == 0 andalso
	mnesia:table_info(catalog_put_fs, size) == 0 andalso
	mnesia:table_info(catalog_delete_fs, size) == 0 andalso
	mnesia:table_info(catalog_options_fs, size) == 0 andalso
	mnesia:table_info(catalog_re_fs, size) == 0 andalso
	mnesia:table_info(catalog_kernel_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) ->	
	mnesia:table_info(catalog_get_db, size) +
	mnesia:table_info(catalog_post_db, size) +
	mnesia:table_info(catalog_put_db, size) +
	mnesia:table_info(catalog_delete_db, size) +
	mnesia:table_info(catalog_options_db, size) +
	mnesia:table_info(catalog_re_db, size) +
	mnesia:table_info(catalog_kernel_db, size);
size_table(fs) ->	
	mnesia:table_info(catalog_get_fs, size) +
	mnesia:table_info(catalog_post_fs, size) +
	mnesia:table_info(catalog_put_fs, size) +
	mnesia:table_info(catalog_delete_fs, size) +
	mnesia:table_info(catalog_options_fs, size) +
	mnesia:table_info(catalog_re_fs, size) +
	mnesia:table_info(catalog_kernel_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(catalog_get_db) of
		{atomic, ok} -> 
			case mnesia:clear_table(catalog_post_db) of
				{atomic, ok} -> 
					case mnesia:clear_table(catalog_put_db) of
						{atomic, ok} ->
							case mnesia:clear_table(catalog_delete_db) of
								{atomic, ok} -> 
									case mnesia:clear_table(catalog_options_db) of
										{atomic, ok} -> 									
											case mnesia:clear_table(catalog_re_db) of
												{atomic, ok} -> 
													case mnesia:clear_table(catalog_kernel_db) of
														{atomic, ok} -> ok;
														_ -> {error, efail_clear_ets_table}
													end;
												_ -> {error, efail_clear_ets_table}
											end;
										_ -> {error, efail_clear_ets_table}
									end;
								_ -> {error, efail_clear_ets_table}
							end;
						_ -> {error, efail_clear_ets_table}
					end;
				_ -> {error, efail_clear_ets_table}
			end;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(catalog_get_fs) of
		{atomic, ok} -> 
			case mnesia:clear_table(catalog_post_fs) of
				{atomic, ok} -> 
					case mnesia:clear_table(catalog_put_fs) of
						{atomic, ok} ->
							case mnesia:clear_table(catalog_delete_fs) of
								{atomic, ok} -> 
									case mnesia:clear_table(catalog_options_fs) of
										{atomic, ok} -> 									
											case mnesia:clear_table(catalog_re_fs) of
												{atomic, ok} -> 
													case mnesia:clear_table(catalog_kernel_fs) of
														{atomic, ok} -> ok;
														_ -> {error, efail_clear_ets_table}
													end;
												_ -> {error, efail_clear_ets_table}
											end;
										_ -> {error, efail_clear_ets_table}
									end;
								_ -> {error, efail_clear_ets_table}
							end;
						_ -> {error, efail_clear_ets_table}
					end;
				_ -> {error, efail_clear_ets_table}
			end;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) ->	
	ems_db:init_sequence(catalog_get_db, 0),
	ems_db:init_sequence(catalog_post_db, 0),
	ems_db:init_sequence(catalog_put_db, 0),
	ems_db:init_sequence(catalog_delete_db, 0),
	ems_db:init_sequence(catalog_options_db, 0),
	ems_db:init_sequence(catalog_re_db, 0),
	ems_db:init_sequence(catalog_kernel_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(catalog_get_fs, 0),
	ems_db:init_sequence(catalog_post_fs, 0),
	ems_db:init_sequence(catalog_put_fs, 0),
	ems_db:init_sequence(catalog_delete_fs, 0),
	ems_db:init_sequence(catalog_options_fs, 0),
	ems_db:init_sequence(catalog_re_fs, 0),
	ems_db:init_sequence(catalog_kernel_fs, 0),
	ok.
	
	
-spec check_remove_records(list(), fs | db) -> non_neg_integer().	
check_remove_records(_Codigos, _SourceType) -> 0.
	

%% internal functions

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.cat_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert_update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_catalog:new_from_map(Map, Conf) of
			{ok, NewCatalog = #service{type = ServiceType, use_re = UseRE, rowid = Rowid, ctrl_modified = CtrlModified, ctrl_hash = CtrlHash, enable = Enable}} when Enable == true -> 
				Table = ems_catalog:get_table(ServiceType, UseRE, SourceType),
				case ems_catalog_lookup:find(Table, Rowid) of
					{error, enoent} -> 
						Catalog = NewCatalog#service{ctrl_insert = CtrlDate},
						{ok, Catalog, Table, insert};
					{ok, CurrentCatalog = #service{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								?DEBUG("ems_catalog_loader_middleware update ~p from ~p.", [Map, SourceType]),
								Catalog = CurrentCatalog#service{
												name = NewCatalog#service.name,
												url = NewCatalog#service.url,
												type = NewCatalog#service.type,
												service = NewCatalog#service.service,
												module_name = NewCatalog#service.module_name,
												module_name_canonical = NewCatalog#service.module_name_canonical,
												module = NewCatalog#service.module,
												function_name = NewCatalog#service.function_name,
												function = NewCatalog#service.function,
												public = NewCatalog#service.public,
												owner = NewCatalog#service.owner,
												group = NewCatalog#service.group,
												glyphicon = NewCatalog#service.glyphicon,
												async = NewCatalog#service.async,
												querystring = NewCatalog#service.querystring,
												qtd_querystring_req = NewCatalog#service.qtd_querystring_req,
												host = NewCatalog#service.host,
												host_name = NewCatalog#service.host_name,
												result_cache = NewCatalog#service.result_cache,
												authorization = NewCatalog#service.authorization,
												node = NewCatalog#service.node,
												page = NewCatalog#service.page,
												page_module = NewCatalog#service.page_module,
												datasource = NewCatalog#service.datasource,
												debug = NewCatalog#service.debug,
												lang = NewCatalog#service.lang,
												schema_in = NewCatalog#service.schema_in,
												schema_out = NewCatalog#service.schema_out,
												pool_size = NewCatalog#service.pool_size,
												pool_max = NewCatalog#service.pool_max,
												timeout = NewCatalog#service.timeout,
												timeout_alert_threshold = NewCatalog#service.timeout_alert_threshold,
												middleware = NewCatalog#service.middleware,
												properties = NewCatalog#service.properties,
												cache_control = NewCatalog#service.cache_control,
												expires = NewCatalog#service.expires,
												content_type = NewCatalog#service.content_type,
												ctrl_path = NewCatalog#service.ctrl_path,
												ctrl_file = NewCatalog#service.ctrl_file,
												path = NewCatalog#service.path,
												redirect_url = NewCatalog#service.redirect_url,
												enable = NewCatalog#service.enable,
												tcp_listen_address = NewCatalog#service.tcp_listen_address,
												tcp_listen_address_t = NewCatalog#service.tcp_listen_address_t,
												tcp_allowed_address = NewCatalog#service.tcp_allowed_address,
												tcp_allowed_address_t = NewCatalog#service.tcp_allowed_address_t,
												tcp_max_connections = NewCatalog#service.tcp_max_connections,
												tcp_port = NewCatalog#service.tcp_port,
												tcp_is_ssl = NewCatalog#service.tcp_is_ssl,
												tcp_ssl_cacertfile = NewCatalog#service.tcp_ssl_cacertfile,
												tcp_ssl_certfile = NewCatalog#service.tcp_ssl_certfile,
												tcp_ssl_keyfile = NewCatalog#service.tcp_ssl_keyfile,
												oauth2_with_check_constraint = NewCatalog#service.oauth2_with_check_constraint,
												oauth2_token_encrypt = NewCatalog#service.oauth2_token_encrypt,
												oauth2_allow_client_credentials = NewCatalog#service.oauth2_allow_client_credentials,
												auth_allow_user_inative_credentials = NewCatalog#service.auth_allow_user_inative_credentials,
												authorization_public_check_credential = NewCatalog#service.authorization_public_check_credential,
												protocol = NewCatalog#service.protocol,
												filename = NewCatalog#service.filename,
												http_max_content_length = NewCatalog#service.http_max_content_length,
												http_headers = NewCatalog#service.http_headers,
												log_show_response = NewCatalog#service.log_show_response,
												log_show_payload = NewCatalog#service.log_show_payload,
												restricted = NewCatalog#service.restricted,
												ctrl_update = CtrlDate,
												ctrl_modified = CtrlModified,
												ctrl_hash = CtrlHash
											},
								{ok, Catalog, Table, update};
							false -> {ok, skip}
						end
				end;
			{ok, _} -> {ok, skip};
			Error -> Error
		end

	catch
		_Exception:Reason -> {error, Reason}
	end.

-spec after_load_or_update_checkpoint(fs | db) -> ok.
after_load_or_update_checkpoint(_SourceType) ->	ok.
