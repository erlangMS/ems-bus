%%********************************************************************
%% @title Module ems_catalog
%% @version 1.0.0
%% @doc Module responsible for catalog management services
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_catalog).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([new_from_map/2, 
		 get_metadata_json/1,
		 get_table/3,
		 find_by_rowid/1]).
		 
		 
-spec find_by_rowid(non_neg_integer()) -> {ok, #service{}} | {error, enoent}.
find_by_rowid(RowId) -> 
	case ems_db:get([catalog_get_fs, catalog_post_fs, catalog_put_fs, catalog_delete_fs, catalog_options_fs, catalog_kernel_fs,
					 catalog_get_db, catalog_post_db, catalog_put_db, catalog_delete_db, catalog_options_db, catalog_kernel_db], RowId) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.
		 

-spec get_metadata_json(#service{}) -> binary().
get_metadata_json(#service{id = Id,
						  name = Name,
						  content_type = ContentType,
						  type = Type,
						  url = Url,
						  service = Service,
						  comment = Comment,
						  version = Version,
						  owner = Owner,
						  group = Group,
						  result_cache = ResultCache,
						  authorization = Authorization,
						  timeout = Timeout,
						  glyphicon = Glyphicon,
						  ctrl_path = CtrlPath,
						  ctrl_file = CtrlFile,
						  path = Path,
						  lang = Lang,
						  querystring = Querystring,
						  cache_control = CacheControl}) ->
	iolist_to_binary([<<"{"/utf8>>,
					   <<"\"id\""/utf8>>, <<":"/utf8>>, integer_to_binary(Id), <<","/utf8>>,
					   <<"\"name\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Name, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"content_type\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, ContentType, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"type\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Type, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"service\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Service, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"url\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Url, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"comment\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Comment, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"version\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Version, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"owner\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Owner, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"group\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Group, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"glyphicon\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Glyphicon, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"result_cache\""/utf8>>, <<":"/utf8>>, integer_to_binary(ResultCache), <<","/utf8>>,
					   <<"\"timeout\""/utf8>>, <<":"/utf8>>, integer_to_binary(Timeout), <<","/utf8>>,
					   <<"\"cache_control\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, CacheControl, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"ctrl_path\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, case CtrlPath of
																			undefined -> <<>>;
																			_ -> CtrlPath
																		 end, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"ctrl_file\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, case CtrlFile of
																			undefined -> <<>>;
																			_ -> CtrlFile
																		 end, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"path\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, case Path of
																			undefined -> <<>>;
																			_ -> Path
																		 end, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"lang\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Lang, <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"authorization\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, erlang:atom_to_binary(Authorization, utf8), <<"\""/utf8>>, <<","/utf8>>,
					   <<"\"querystring\""/utf8>>, <<":"/utf8>>, ems_util:json_encode(Querystring),
				   <<"}"/utf8>>]).



new_service_re(Rowid, Id, Name, Url, Service, ModuleName, ModuleNameCanonical, FunctionName, 
			   Type, Enable, Comment, Version, Owner, Group, Glyphicon, Async, Querystring, 
			   QtdQuerystringRequired, Host, HostName, ResultCache, ResultCacheShared,
			   Authorization, Node, Lang, Datasource,
			   Debug, SchemaIn, SchemaOut, PoolSize, PoolMax, Properties,
			   Timeout, TimeoutAlertThreshold,
			   Middleware, CacheControl, 
			   ExpiresMinute, Public, ContentType, Path, Filename,
			   RedirectUrl, ListenAddress, ListenAddress_t, AllowedAddress, 
			   AllowedAddress_t, Port, MaxConnections,
			   IsSsl, SslCaCertFile, SslCertFile, SslKeyFile,
			   OAuth2WithCheckConstraint, OAuth2TokenEncrypt, OAuth2AllowClientCredentials, AuthAllowUserInativeCredentials,
			   Protocol,
			   CtrlPath, CtrlFile, CtrlModified, StartTimeout, CtrlHash,
			   ServiceExecMetricName, 
			   ServiceResultCacheHitMetricName, 
			   ServiceHostDeniedMetricName,	ServiceAuthDeniedMetricName, 
			   ServiceErrorMetricName, ServiceUnavailableMetricName,
			   ServiceTimeoutMetricName, 
			   ServiceResendMsg1, 
			   AuthorizationPublicCheckCredential,
			   HttpMaxContentLength, HttpHeaders, 
			   LogShowResponse, LogShowPayload, Restricted,
			   ShowDebugResponseHeader) ->
	PatternKey = ems_util:make_rowid_from_url(Url, Type),
	{ok, Id_re_compiled} = re:compile(PatternKey),
	Contract = #service{
					id = Id,
					rowid = Rowid,
					name = Name,
					url = Url,
					type = Type,
					service = Service,
					module_name = ModuleName,
					module_name_canonical = ModuleNameCanonical,
					module = list_to_atom(ModuleName),
					function_name = FunctionName,
					function = list_to_atom(FunctionName),
					use_re = true,
					id_re_compiled = Id_re_compiled,
					public = Public,
					comment = Comment,
					version = Version,
					owner = Owner,
					glyphicon = Glyphicon,
					group = Group,
					async = Async,
					querystring = Querystring,
					qtd_querystring_req = QtdQuerystringRequired,
					host = Host,
					host_name = HostName,
					result_cache = ResultCache,
					result_cache_shared = ResultCacheShared,
					authorization = Authorization,
					node = Node,
					datasource = Datasource,
					debug = Debug,
					lang = Lang,
					schema_in = SchemaIn,
					schema_out = SchemaOut,
					pool_size = PoolSize,
					pool_max = PoolMax,
					timeout = Timeout,
					timeout_alert_threshold = TimeoutAlertThreshold,
					middleware = Middleware,
					properties = Properties,
					cache_control = CacheControl,
					expires = ExpiresMinute,
					content_type = ContentType,
					ctrl_path = CtrlPath,
					ctrl_file = CtrlFile,
					path = Path,
					filename = Filename,
					redirect_url = RedirectUrl,
					enable = Enable,
					tcp_listen_address = ListenAddress,
					tcp_listen_address_t = ListenAddress_t,
					tcp_allowed_address = AllowedAddress,
					tcp_allowed_address_t = AllowedAddress_t,
					tcp_max_connections = MaxConnections,
					tcp_port = Port,
					tcp_is_ssl = IsSsl,
					tcp_ssl_cacertfile = SslCaCertFile,
					tcp_ssl_certfile = SslCertFile,
					tcp_ssl_keyfile = SslKeyFile,
					oauth2_with_check_constraint = OAuth2WithCheckConstraint,
					oauth2_token_encrypt = OAuth2TokenEncrypt,
					oauth2_allow_client_credentials = OAuth2AllowClientCredentials,
					auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials,
					protocol = Protocol,
					ctrl_modified = CtrlModified,
					ctrl_hash = CtrlHash,
					start_timeout = StartTimeout,
					service_exec_metric_name = ServiceExecMetricName,
					service_result_cache_hit_metric_name = ServiceResultCacheHitMetricName,
					service_host_denied_metric_name = ServiceHostDeniedMetricName,
					service_auth_denied_metric_name = ServiceAuthDeniedMetricName,
					service_error_metric_name = ServiceErrorMetricName,
					service_unavailable_metric_name = ServiceUnavailableMetricName,
					service_timeout_metric_name = ServiceTimeoutMetricName,
					service_resend_msg1 = ServiceResendMsg1,
					authorization_public_check_credential = AuthorizationPublicCheckCredential,
					http_max_content_length = HttpMaxContentLength,
					http_headers = HttpHeaders,
					log_show_response = LogShowResponse,
					log_show_payload = LogShowPayload,
					restricted = Restricted,
					show_debug_response_headers = ShowDebugResponseHeader
				},
	Contract#service{metadata = get_metadata_json(Contract)}.
	

new_service(Rowid, Id, Name, Url, Service, ModuleName, ModuleNameCanonical, FunctionName,
			Type, Enable, Comment, Version, Owner, Group, Glyphicon, Async, Querystring, 
			QtdQuerystringRequired, Host, HostName, ResultCache, ResultCacheShared,
			Authorization, Node, Lang, Datasource, Debug, SchemaIn, SchemaOut, 
			PoolSize, PoolMax, Properties, Timeout, TimeoutAlertThreshold,
			Middleware, CacheControl, ExpiresMinute, Public, 
			ContentType, Path, Filename,
			RedirectUrl, ListenAddress, ListenAddress_t, AllowedAddress, AllowedAddress_t, 
			Port, MaxConnections, IsSsl, SslCaCertFile, SslCertFile, SslKeyFile,
			OAuth2WithCheckConstraint, OAuth2TokenEncrypt, OAuth2AllowClientCredentials, AuthAllowUserInativeCredentials,
			Protocol, 
			CtrlPath, CtrlFile, CtrlModified, StartTimeout, CtrlHash,
			ServiceExecMetricName, ServiceResultCacheHitMetricName, 
			ServiceHostDeniedMetricName, ServiceAuthDeniedMetricName, 
			ServiceErrorMetricName, ServiceUnavailableMetricName,
			ServiceTimeoutMetricName, 
		    ServiceResendMsg1, 
			AuthorizationPublicCheckCredential,
			HttpMaxContentLength, HttpHeaders, 
			LogShowResponse, LogShowPayload, Restricted,
			ShowDebugResponseHeader) ->
	Contract = #service{
				id = Id,
				rowid = Rowid,
				name = Name,
				url = Url,
				type = Type,
				service = Service,
			    module_name = ModuleName,
			    module_name_canonical = ModuleNameCanonical,
			    module = list_to_atom(ModuleName),
			    function_name = FunctionName,
			    function = list_to_atom(FunctionName),
			    public = Public,
			    comment = Comment,
			    version = Version,
			    owner = Owner,
			    group = Group,
			    glyphicon = Glyphicon,
			    async = Async,
			    querystring = Querystring,
			    qtd_querystring_req = QtdQuerystringRequired,
			    host = Host,
			    host_name = HostName,
			    result_cache = ResultCache,
			    result_cache_shared = ResultCacheShared,
			    authorization = Authorization,
			    node = Node,
			    datasource = Datasource,
			    debug = Debug,
			    lang = Lang,
			    schema_in = SchemaIn,
			    schema_out = SchemaOut,
			    pool_size = PoolSize,
			    pool_max = PoolMax,
			    timeout = Timeout,
			    timeout_alert_threshold = TimeoutAlertThreshold,
			    middleware = Middleware,
			    properties = Properties,
			    cache_control = CacheControl,
			    expires = ExpiresMinute,
			    content_type = ContentType,
			    ctrl_path = CtrlPath,
			    ctrl_file = CtrlFile,
			    path = Path,
			    filename = Filename,
			    redirect_url = RedirectUrl,
			    enable = Enable,
				tcp_listen_address = ListenAddress,
				tcp_listen_address_t = ListenAddress_t,
				tcp_allowed_address = AllowedAddress,
				tcp_allowed_address_t = AllowedAddress_t,
				tcp_max_connections = MaxConnections,
				tcp_port = Port,
				tcp_is_ssl = IsSsl,
				tcp_ssl_cacertfile = SslCaCertFile,
				tcp_ssl_certfile = SslCertFile,
				tcp_ssl_keyfile = SslKeyFile,
				oauth2_with_check_constraint = OAuth2WithCheckConstraint,
				oauth2_token_encrypt = OAuth2TokenEncrypt,
				oauth2_allow_client_credentials = OAuth2AllowClientCredentials,
				auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials,
				protocol = Protocol,
				ctrl_modified = CtrlModified,
				ctrl_hash = CtrlHash,
				start_timeout = StartTimeout,
				service_exec_metric_name = ServiceExecMetricName,
				service_result_cache_hit_metric_name = ServiceResultCacheHitMetricName,
				service_host_denied_metric_name = ServiceHostDeniedMetricName,
				service_auth_denied_metric_name = ServiceAuthDeniedMetricName,
				service_error_metric_name = ServiceErrorMetricName,
				service_unavailable_metric_name = ServiceUnavailableMetricName,
				service_timeout_metric_name = ServiceTimeoutMetricName,
				service_resend_msg1 = ServiceResendMsg1,
				authorization_public_check_credential = AuthorizationPublicCheckCredential,
				http_max_content_length = HttpMaxContentLength,
				http_headers = HttpHeaders,
				log_show_response = LogShowResponse,
				log_show_payload = LogShowPayload,
				restricted = Restricted,
				show_debug_response_headers = ShowDebugResponseHeader
			},
	Contract#service{metadata = get_metadata_json(Contract)}.

parse_middleware(null) -> undefined;
parse_middleware(undefined) -> undefined;
parse_middleware(Middleware) -> erlang:binary_to_atom(Middleware, utf8).

parse_ssl_path(FilenameCat, FilenameConfig, StaticFilePathDefault) -> 
	case FilenameConfig of
		undefined -> Filename = ems_util:parse_file_name_path(FilenameCat, StaticFilePathDefault, ?SSL_PATH);
		_ -> Filename = Filename = ems_util:parse_file_name_path(FilenameConfig, StaticFilePathDefault, ?SSL_PATH)
	end,
	case filelib:is_regular(Filename) of
		true -> list_to_binary(Filename);
		false -> 
			ems_logger:error("ems_catalog parse invalid ssl filename ~p.", [Filename]),
			erlang:error(einvalid_ssl_config_service)
	end.
	


-spec parse_datasource(map(), non_neg_integer(), #config{}) -> #service_datasource{} | undefined.
parse_datasource(undefined, _, _) -> undefined;
parse_datasource(M, Rowid, Conf) when erlang:is_map(M) -> ems_db:create_datasource_from_map(M, Rowid, Conf);
parse_datasource(DsName, _Rowid, Conf) -> 
	case maps:get(DsName, Conf#config.ems_datasources, undefined) of
		undefined -> erlang:error(einexistent_datasource);
		Ds -> Ds
	end.
		
		

	
parse_node_service(undefined) -> <<>>;
parse_node_service(<<>>) -> <<>>;
parse_node_service(List) -> List.

%% @doc O host pode ser um alias definido no arquivo de configuração
-ifdef(win32_plataform).
parse_host_service(<<>>, _,_,_) -> {'', atom_to_list(node())};
parse_host_service(_Host, ModuleName, Node, Conf) ->
	ModuleNameCanonical = [case X of 46 -> 95; _ -> X end || X <- ModuleName], % Troca . por _
	ListHost = case net_adm:host_file() of
		{error, _Reason} -> [Conf#config.ems_host];
		Hosts -> Hosts
	end,
	case erlang:is_list(Node) of
		true  -> ListNode = Node;
		false -> ListNode = [Node]
	end,
	ListHost2 = [case string:tokens(atom_to_list(X), ".") of
					[N, _] -> N;
					[N] -> N
				 end || X <- ListHost],
	ListNode2 = lists:map(fun(X) -> binary_to_list(X) end, ListNode),
	ClusterName = [case X of
						[] -> ModuleNameCanonical ++ K  ++ "@" ++ Y;
						_  -> ModuleNameCanonical ++ K ++ "_" ++ X ++ "@" ++ Y 
				   end || X <- ListNode2, Y <- ListHost2, K <- [""]],
	ClusterNode = lists:map(fun(X) -> list_to_atom(X) end, ClusterName),
	{ClusterNode, ClusterName}.
-else.
parse_host_service(<<>>, _,_,_) -> {'', atom_to_list(node())};
parse_host_service(_Host, ModuleName, Node, Conf) ->
	ModuleNameCanonical = [case X of 46 -> 95; _ -> X end || X <- ModuleName], % Troca . por _
	ListHost = case net_adm:host_file() of
		{error, _Reason} -> [Conf#config.ems_host];
		Hosts -> Hosts
	end,
	case erlang:is_list(Node) of
		true  -> ListNode = Node;
		false -> ListNode = [Node]
	end,
	ListHost2 = [case string:tokens(atom_to_list(X), ".") of
					[N, _] -> N;
					[N] -> N
				 end || X <- ListHost],
	ListNode2 = lists:map(fun(X) -> binary_to_list(X) end, ListNode),
	ClusterName = [case X of
						[] -> ModuleNameCanonical ++ K  ++ "@" ++ Y;
						_  -> ModuleNameCanonical ++ K ++ "_" ++ X ++ "@" ++ Y 
				   end || X <- ListNode2, Y <- ListHost2, K <- ["", "02"]],
	ClusterNode = lists:map(fun(X) -> list_to_atom(X) end, ClusterName),
	{ClusterNode, ClusterName}.
-endif.


get_p(ParamName, Map, DefaultValue) ->
	Result = maps:get(ParamName, Map, DefaultValue),
	case is_binary(Result) of
		true -> ems_util:replace_config_and_custom_variables_binary(Result);
		false -> Result
	end.

-spec new_from_map(map(), #config{}) -> {ok, #service{}} | {error, atom()}.
new_from_map(Map, Conf = #config{cat_enable_services = EnableServices,
								 cat_disable_services = DisableServices,
								 cat_enable_services_owner = EnableServicesOwner,
								 cat_disable_services_owner = DisableServicesOwner,
								 cat_restricted_services_owner = RestrictedServicesOwner,
								 ems_result_cache = ResultCacheDefault,
								 ems_result_cache_shared = ResultCacheSharedDefault,
								 ems_result_cache_enabled = ResultCacheEnabledDefault,
								 ems_hostname = HostNameDefault,
								 authorization = AuthorizationDefault,
								 oauth2_with_check_constraint = Oauth2WithCheckConstraintDefault,
								 static_file_path = StaticFilePathDefault,
								 tcp_listen_address_t = TcpListenAddressDefault,
								 tcp_allowed_address = TcpAllowedAddressDefault,
								 tcp_listen_prefix_interface_names = TcpListenPrefixInterfaceNamesDefault,
								 cat_node_search = CatNodeSearchDefault,
								 cat_host_search = CatHostSearchDefault,
								 ssl_cacertfile = SslCaCertFileDefault,
								 ssl_certfile = SslCertFileDefault,
								 ssl_keyfile = SslKeyFileDefault,
								 http_max_content_length = HttpMaxContentLengthDefault,
								 http_headers = HttpHeadersDefault,
								 rest_default_querystring = RestDefaultQuerystring,
								 auth_allow_user_inative_credentials = AuthAllowUserInativeCredentialsDefault,
								 show_debug_response_headers = ShowDebugResponseHeadersDefault,
								 log_show_response = LogShowResponseDefault,
								 log_show_payload = LogShowPayloadDefault, 
								 instance_type = InstanceType}) ->
	try
		put(parse_step, name),
		Name = ems_util:parse_name_service(get_p(<<"name">>, Map, <<>>)),
		
		put(parse_step, owner),
		Owner = get_p(<<"owner">>, Map, <<>>),

		% habilitar serviços
		put(parse_step, enable),
		Enable0 = ems_util:parse_bool(get_p(<<"enable">>, Map, true)),
		case lists:member(Owner, EnableServicesOwner) of
			true -> Enable1 = true;
			false -> Enable1 = Enable0
		end,
		case lists:member(Name, EnableServices) of
			true -> Enable2 = true;
			false -> Enable2 = Enable1
		end,
		case lists:member(Owner, DisableServicesOwner) of
			true -> Enable3 = false;
			false -> Enable3 = Enable2
		end,
		case lists:member(Name, DisableServices) of
			true -> Enable = false;
			false -> Enable = Enable3
		end,

		case Enable of
			true ->
				ems_logger:debug("ems_catalog loading catalog ~p of owner ~p.", [binary_to_list(Name), binary_to_list(Owner)]),
				
				put(parse_step, ctrl_path),
				CtrlPath = get_p(<<"ctrl_path">>, Map, <<>>),
				
				put(parse_step, ctrl_file),
				CtrlFile = get_p(<<"ctrl_file">>, Map, <<>>),

				put(parse_step, group),
				Group = get_p(<<"group">>, Map, <<>>),
				
				put(parse_step, glyphicon),
				Glyphicon = get_p(<<"glyphicon">>, Map, <<>>),

				put(parse_step, restricted),
				Restricted0 = get_p(<<"restricted">>, Map, undefined),
				case Restricted0 of
					undefined -> Restricted = lists:member(Owner, RestrictedServicesOwner);
					_ -> Restricted = ems_util:parse_bool(Restricted0)
				end,

				put(parse_step, use_re),
				UseRE = ems_util:parse_bool(get_p(<<"use_re">>, Map, false)),
				case UseRE of
					true -> 
						put(parse_step, url),
						Url2 = get_p(<<"url">>, Map, <<>>);
					false -> 
						put(parse_step, url),
						Url2 = ems_util:parse_url_service(get_p(<<"url">>, Map, <<>>))
				end,
				UrlStr = binary_to_list(Url2),

				% Valida a URL (se não tem expressão regular) e adverte como um warning se tem verbos de ligação ou está em maiúscula
				case UseRE of
					false ->
						case (string:to_lower(UrlStr) /= UrlStr) 
							orelse string:len(UrlStr) > 160 
							orelse ems_util:str_contains(UrlStr, ["salva", "gera", "confirma", "cancela", "busca", "avisa", "possui", "validar", "conclui", "listar", "listagem", "carrega", "obter", "garante", "altera", "exclui", "atualiza", "processa"]) of
								true -> ems_logger:format_warn("ems_catalog url \033[01;34m~p\033[0m does not comply good RESTful practices. Use short URLs in lowercase without unnecessary articles or link verbs.", [UrlStr]);
								false -> ok
						end;
					true -> ok
				end,

				put(parse_step, type),
				Type = ems_util:parse_type_service(get_p(<<"type">>, Map, <<"GET">>)),
				
				put(parse_step, service),
				ServiceImpl = get_p(<<"service">>, Map, <<>>),
				{ModuleName, ModuleNameCanonical, FunctionName} = ems_util:parse_service_service(ServiceImpl),
				
				put(parse_step, comment),
				case CtrlFile =:= <<>> of
					true ->  Comment = ?UTF8_STRING(get_p(<<"comment">>, Map, <<>>));
					false -> Comment = get_p(<<"comment">>, Map, <<>>)
				end,
				
				put(parse_step, version),
				Version = get_p(<<"version">>, Map, <<"1.0.0">>),
				
				put(parse_step, async),
				Async = ems_util:parse_bool(get_p(<<"async">>, Map, false)),

				put(parse_step, show_debug_response_headers),
				ShowDebugResponseHeader = ems_util:parse_bool(get_p(<<"show_debug_response_headers">>, Map, ShowDebugResponseHeadersDefault)),

				put(parse_step, make_rowid),
				Rowid = ems_util:make_rowid(Url2),

				put(parse_step, id),
				Id = get_p(<<"id">>, Map, Rowid), % catálogos internos vão usar rowid como chave primária

				put(parse_step, lang),
				Lang = ems_util:parse_lang(get_p(<<"lang">>, Map, <<>>)),
				
				put(parse_step, datasource),
				Ds = get_p(<<"datasource">>, Map, undefined),
				case Enable of
					true ->	Datasource = parse_datasource(Ds, Rowid, Conf);
					false -> Datasource = undefined
				end,
				
				put(parse_step, result_cache),
				case ResultCacheEnabledDefault of
					true ->
						case Type of
							<<"GET">> -> ResultCache = ems_util:parse_result_cache(get_p(<<"result_cache">>, Map, ResultCacheDefault));
							_ -> ResultCache = 0
						end;
					false -> ResultCache = 0
				end,

				put(parse_step, result_cache_shared),
				ResultCacheShared = get_p(<<"result_cache_shared">>, Map, ResultCacheSharedDefault),
				
				put(parse_step, authorization),
				Authorization = ems_util:parse_authorization_type(get_p(<<"authorization">>, Map, AuthorizationDefault)),
				
				put(parse_step, oauth2_with_check_constraint),
				OAuth2WithCheckConstraint = ems_util:parse_bool(get_p(<<"oauth2_with_check_constraint">>, Map, Oauth2WithCheckConstraintDefault)),
				
				put(parse_step, oauth2_token_encrypt),
				OAuth2TokenEncrypt = ems_util:parse_bool(get_p(<<"oauth2_token_encrypt">>, Map, false)),
				
				put(parse_step, oauth2_allow_client_credentials),
				OAuth2AllowClientCredentials = ems_util:parse_bool(get_p(<<"oauth2_allow_client_credentials">>, Map, false)),
				
				put(parse_step, auth_allow_user_inative_credentials),
				AuthAllowUserInativeCredentials = ems_util:parse_bool(get_p(<<"auth_allow_user_inative_credentials">>, Map, AuthAllowUserInativeCredentialsDefault)),
				
				put(parse_step, authorization_public_check_credential),
				AuthorizationPublicCheckCredential = ems_util:parse_bool(get_p(<<"authorization_public_check_credential">>, Map, false)),
				
				put(parse_step, debug),
				Debug = ems_util:parse_bool(get_p(<<"debug">>, Map, false)),
				
				put(parse_step, schema_in),
				SchemaIn = get_p(<<"schema_in">>, Map, null),
				
				put(parse_step, schema_out),
				SchemaOut = get_p(<<"schema_out">>, Map, null),
				
				put(parse_step, pool_size),
				PoolSize = ems_config:getConfig(<<"pool_size">>, Name, get_p(<<"pool_size">>, Map, 1)),
				
				put(parse_step, pool_max),
				PoolMax0 = ems_config:getConfig(<<"pool_max">>, Name, get_p(<<"pool_max">>, Map, 1)),
				% Ajusta o pool_max para o valor de pool_size se for menor
				case PoolMax0 < PoolSize of
					true -> PoolMax = PoolSize;
					false -> PoolMax = PoolMax0
				end,
				
				put(parse_step, timeout),
				Timeout = ems_util:parse_range(get_p(<<"timeout">>, Map, ?SERVICE_TIMEOUT), ?SERVICE_MIN_TIMEOUT, ?SERVICE_MAX_TIMEOUT, einvalid_timeout_service),
				
				put(parse_step, timeout_alert_threshold),
				TimeoutAlertThreshold = ems_util:parse_range(get_p(<<"timeout_alert_threshold">>, Map, 0), 0, Timeout, einvalid_timeout_alert_threshold),
				
				put(parse_step, middleware),
				Middleware = parse_middleware(get_p(<<"middleware">>, Map, undefined)),
				
				put(parse_step, cache_control),
				case InstanceType of
					production ->
						CacheControlValue = get_p(<<"cache_control">>, Map, ?CACHE_CONTROL_NO_CACHE),
						case CacheControlValue of
							<<"no-cache">> -> 
								CacheControl = ?CACHE_CONTROL_NO_CACHE;
							_ -> CacheControl = CacheControlValue
						end;
					_ -> 
						CacheControl = ?CACHE_CONTROL_NO_CACHE
				end,

				put(parse_step, expires_minute),
				case maps:is_key(<<"expires_minute">>, Map) of
					true -> ExpiresMinute = ems_util:parse_range(get_p(<<"expires_minute">>, Map, 0), ?SERVICE_MIN_EXPIRE_MINUTE, ?SERVICE_MAX_EXPIRE_MINUTE, einvalid_expires_minute);
					false -> ExpiresMinute = ems_util:parse_range(get_p(<<"expires">>, Map, 0), ?SERVICE_MIN_EXPIRE_MINUTE, ?SERVICE_MAX_EXPIRE_MINUTE, einvalid_expires_minute)
				end,
				
				put(parse_step, public),
				Public = ems_util:parse_bool(get_p(<<"public">>, Map, true)),
				
				put(parse_step, content_type),
				ContentType0 = ems_util:parse_content_type(case maps:is_key(<<"content_type">>, Map) of
																true ->  get_p(<<"content_type">>, Map, ?CONTENT_TYPE_JSON);
																false -> get_p(<<"content-type">>, Map, ?CONTENT_TYPE_JSON)
														  end),
				% Se for application/json substitui pelo application/json; charset=utf-8
				case ContentType0 of
					<<"application/json">> -> ContentType = ?CONTENT_TYPE_JSON;  
					<<"json">> -> ContentType = ?CONTENT_TYPE_JSON;  
					_ -> ContentType = ContentType0
				end,
				
				put(parse_step, path),
				Path0 = ems_util:parse_file_name_path(get_p(<<"path">>, Map, CtrlPath), StaticFilePathDefault, undefined),
				% Vamos substituir todas as variáveis não encontradas pelo caminho base do catálogo
				% Quando a pasta for assets, então o caminho base é sem o assets
				case filename:basename(CtrlPath) =:= "assets" of
					true -> Path = ems_util:replace_vars_with(Path0, string:slice(CtrlPath, 0, length(CtrlPath) - 7));
					false -> Path = ems_util:replace_vars_with(Path0, CtrlPath)
				end,
				
				put(parse_step, filename),
				Filename = ems_util:parse_file_name_path(get_p(<<"filename">>, Map, undefined), StaticFilePathDefault, undefined),
				
				put(parse_step, redirect_url),
				RedirectUrl = get_p(<<"redirect_url">>, Map, undefined),
				
				put(parse_step, protocol),
				Protocol = get_p(<<"protocol">>, Map, <<>>),
				
				put(parse_step, tcp_listen_prefix_interface_names),
				case maps:is_key(<<"tcp_listen_prefix_interface_names">>, Map) of
					true -> TcpListenPrefixInterfaceNames = ems_util:binlist_to_list(get_p(<<"tcp_listen_prefix_interface_names">>, Map, <<>>));
					false -> TcpListenPrefixInterfaceNames = TcpListenPrefixInterfaceNamesDefault
				end,
				
				put(parse_step, tcp_listen_address),
				ListenAddress = get_p(<<"tcp_listen_address">>, Map, TcpListenAddressDefault),
				
				put(parse_step, parse_tcp_listen_address),
				ListenAddress_t = ems_util:parse_tcp_listen_address(ListenAddress, TcpListenPrefixInterfaceNames),
				
				put(parse_step, parse_allowed_address),
				AllowedAddress = ems_util:parse_allowed_address(get_p(<<"tcp_allowed_address">>, Map, TcpAllowedAddressDefault)),
				
				put(parse_step, parse_allowed_address_t),
				AllowedAddress_t = ems_util:parse_allowed_address_t(AllowedAddress),
				
				put(parse_step, tcp_max_connections),
				MaxConnections = get_p(<<"tcp_max_connections">>, Map, ?HTTP_MAX_CONNECTIONS),
				
				put(parse_step, tcp_port),
				Port = ems_util:parse_tcp_port(ems_config:getConfig(<<"tcp_port">>, Name, get_p(<<"tcp_port">>, Map, undefined))),
				
				put(parse_step, http_max_content_length),
				HttpMaxContentLength = ems_util:parse_range(get_p(<<"http_max_content_length">>, Map, HttpMaxContentLengthDefault), 0, ?HTTP_MAX_CONTENT_LENGTH_BY_SERVICE),
				
				put(parse_step, http_headers),
				HttpHeaders0 = get_p(<<"http_headers">>, Map, #{}),
				HttpHeaders = maps:merge(HttpHeaders0, HttpHeadersDefault),
				
				put(parse_step, log_show_response),
				LogShowResponse = ems_util:parse_bool(get_p(<<"log_show_response">>, Map, LogShowResponseDefault)),
				
				put(parse_step, log_show_payload),
				LogShowPayload = ems_util:parse_bool(get_p(<<"log_show_payload">>, Map, LogShowPayloadDefault)),
				
				put(parse_step, tcp_ssl),
				Ssl = get_p(<<"tcp_ssl">>, Map, undefined),
				case Ssl of
					undefined ->
						IsSsl = false,
						SslCaCertFile = undefined,
						SslCertFile = undefined,
						SslKeyFile = undefined;
					_ ->
						IsSsl = true,
						SslCaCertFile = parse_ssl_path(get_p(<<"cacertfile">>, Ssl, SslCaCertFileDefault), SslCaCertFileDefault, StaticFilePathDefault),
						SslCertFile = parse_ssl_path(get_p(<<"certfile">>, Ssl, SslCertFileDefault), SslCertFileDefault, StaticFilePathDefault),
						SslKeyFile = parse_ssl_path(get_p(<<"keyfile">>, Ssl, SslKeyFileDefault), SslKeyFileDefault, StaticFilePathDefault)
				end,
				
				put(parse_step, host),
				case Lang of
					<<"erlang">> -> 
						Node = <<>>,
						Host = '',
						HostName = HostNameDefault,
						ems_util:compile_modulo_erlang(Path, ModuleNameCanonical);
					_ ->	
						Node = parse_node_service(get_p(<<"node">>, Map, CatNodeSearchDefault)),
						{Host, HostName} = parse_host_service(get_p(<<"host">>, Map, CatHostSearchDefault), ModuleName, Node, Conf)
				end,
				
				put(parse_step, querystring),
				{Querystring, QtdQuerystringRequired} = ems_util:parse_querystring_def(get_p(<<"querystring">>, Map, []), RestDefaultQuerystring),
				
				put(parse_step, ctrl_modified),
				CtrlModified = get_p(<<"ctrl_modified">>, Map, undefined),
				
				put(parse_step, phash2),
				CtrlHash = erlang:phash2(Map),
				
				put(parse_step, start_timeout),
				StartTimeout = ems_util:parse_range(get_p(<<"start_timeout">>, Map, ?START_TIMEOUT), ?START_TIMEOUT_MIN, ?START_TIMEOUT_MAX, einvalid_start_timeout),
			
				put(parse_step, metrics),
				ServiceExecMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_exec"),
				ServiceResultCacheHitMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_result_cache_hit"),
				ServiceHostDeniedMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_host_denied"),
				ServiceAuthDeniedMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_auth_denied"),
				ServiceErrorMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_error"),
				ServiceUnavailableMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_unavailable"),
				ServiceTimeoutMetricName = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_timeout"),
				ServiceResendMsg1 = list_to_atom("service_" ++ integer_to_list(Rowid) ++ "_resend_msg1"),
				
				case UseRE of
					true -> 
						put(parse_step, new_service_re),
						Service = new_service_re(Rowid, Id, Name, Url2, 
												   ServiceImpl,
												   ModuleName, 
												   ModuleNameCanonical,
												   FunctionName, Type, Enable, Comment, 
												   Version, Owner, Group, Glyphicon, Async, 
												   Querystring, QtdQuerystringRequired,
												   Host, HostName, ResultCache, ResultCacheShared,
												   Authorization, Node, Lang,
												   Datasource, Debug, SchemaIn, SchemaOut, 
												   PoolSize, PoolMax, Map, Timeout, TimeoutAlertThreshold,
												   Middleware, CacheControl, ExpiresMinute, 
												   Public, ContentType, Path, Filename,
												   RedirectUrl, ListenAddress, ListenAddress_t, AllowedAddress, 
												   AllowedAddress_t, Port, MaxConnections,
												   IsSsl, SslCaCertFile, SslCertFile, SslKeyFile,
												   OAuth2WithCheckConstraint, OAuth2TokenEncrypt, OAuth2AllowClientCredentials, AuthAllowUserInativeCredentials,
												   Protocol,
												   CtrlPath, CtrlFile, CtrlModified, StartTimeout, CtrlHash,
												   ServiceExecMetricName, ServiceResultCacheHitMetricName, 
												   ServiceHostDeniedMetricName,	ServiceAuthDeniedMetricName, 
												   ServiceErrorMetricName, ServiceUnavailableMetricName, 
												   ServiceTimeoutMetricName, 
												   ServiceResendMsg1,
												   AuthorizationPublicCheckCredential,
												   HttpMaxContentLength, HttpHeaders, 
												   LogShowResponse, LogShowPayload,
												   Restricted, ShowDebugResponseHeader);
					false -> 
						put(parse_step, new_service),
						Service = new_service(Rowid, Id, Name, Url2, 
												ServiceImpl,
												ModuleName,
												ModuleNameCanonical,
												FunctionName, Type, Enable, Comment,
												Version, Owner, Group, Glyphicon, Async, 
												Querystring, QtdQuerystringRequired,
												Host, HostName, ResultCache, ResultCacheShared,
												Authorization, Node, Lang,
												Datasource, Debug, SchemaIn, SchemaOut, 
												PoolSize, PoolMax, Map, Timeout, TimeoutAlertThreshold,
												Middleware, CacheControl, 
												ExpiresMinute, Public, 
												ContentType, Path, Filename,
												RedirectUrl, ListenAddress, ListenAddress_t, AllowedAddress, 
												AllowedAddress_t, Port, MaxConnections,
												IsSsl, SslCaCertFile, SslCertFile, SslKeyFile,
												OAuth2WithCheckConstraint, OAuth2TokenEncrypt, OAuth2AllowClientCredentials, AuthAllowUserInativeCredentials,
												Protocol,
												CtrlPath, CtrlFile, CtrlModified, StartTimeout, CtrlHash,
												ServiceExecMetricName, ServiceResultCacheHitMetricName, 
												ServiceHostDeniedMetricName, ServiceAuthDeniedMetricName, 
												ServiceErrorMetricName, ServiceUnavailableMetricName, 
												ServiceTimeoutMetricName, 
												ServiceResendMsg1,
												AuthorizationPublicCheckCredential,
												HttpMaxContentLength, HttpHeaders, 
												LogShowResponse, LogShowPayload,
												Restricted, ShowDebugResponseHeader)
				end,
				{ok, Service};
			false -> 	
				ems_logger:debug("ems_catalog skip disabled catalog ~p of ownwer ~p.", [binary_to_list(Name), binary_to_list(Owner)]),
				{ok, skip}
		end

	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_catalog),
			ems_logger:warn("ems_catalog parse invalid service specification on \033[01;34m~p\033[0m. Reason: ~p\n\t~p.\n", [get(parse_step), Reason, Map]),
			{error, Reason}
	end.

-spec get_table(#service{}, boolean(), fs | db) -> catalog_get_db | catalog_post_db | catalog_put_db | catalog_delete_db | catalog_options_db |
												   catalog_get_fs | catalog_post_fs | catalog_put_fs | catalog_delete_fs | catalog_options_fs.
get_table(_, true, db) -> catalog_re_db;
get_table(_, true, fs) -> catalog_re_fs;
get_table(<<"GET">>, _, db) -> catalog_get_db;
get_table(<<"POST">>, _, db) -> catalog_post_db;
get_table(<<"PUT">>, _, db) -> catalog_put_db;
get_table(<<"DELETE">>, _, db) -> catalog_delete_db;
get_table(<<"OPTIONS">>, _, db) -> catalog_options_db;
get_table(<<"KERNEL">>, _, db) -> catalog_kernel_db;
get_table(<<"GET">>, _, fs) -> catalog_get_fs;
get_table(<<"POST">>, _, fs) -> catalog_post_fs;
get_table(<<"PUT">>, _, fs) -> catalog_put_fs;
get_table(<<"DELETE">>, _, fs) -> catalog_delete_fs;
get_table(<<"OPTIONS">>, _, fs) -> catalog_options_fs;
get_table(<<"KERNEL">>, _, fs) -> catalog_kernel_fs.

