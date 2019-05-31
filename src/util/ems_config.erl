%%********************************************************************
%% @title Module ems_config
%% @version 1.0.0
%% @doc Module for configuration management
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_config).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Server API
-export([start/0, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

-export([getConfig/0, getConfig/3, get_port_offset/1, select_config_file/2, add_catalog/2, remove_catalog/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start() -> 
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 

%%====================================================================
%% Client API
%%====================================================================
 
getConfig() -> ems_db:get_param(config_variables).

-spec getConfig(binary(), binary(), any()) -> any().
getConfig(ParamName, ServiceName, Default) -> gen_server:call(?SERVER, {get_config, ParamName, ServiceName, Default}).

-spec get_port_offset(#service{}) -> non_neg_integer() | undefined.
get_port_offset(S = #service{tcp_port = Port, name = ServiceName}) ->
	Port2 = gen_server:call(?SERVER, {use_port_offset, ServiceName, Port}),
 	S#service{tcp_port = Port2}.

add_catalog(CatName, CatFilename) ->
	gen_server:call(?SERVER, {add_catalog, CatName, CatFilename}),
	ok.

remove_catalog(CatName) ->
	gen_server:call(?SERVER, {remove_catalog, CatName}),
	ok.


%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init([]) -> 
	try
		ets:new(debug_ets, [set, named_table, public, {read_concurrency, true}, {write_concurrency, false}]),
		ets:insert(debug_ets, {debug, false}),
		Config = load_config(),
		{ok, Config}
	catch _Exception: Reason ->
		{stop, Reason}
	end.

    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.
    
handle_call(get_config, _From, State) ->
	{reply, State, State};

handle_call({get_config, ParamName, ServiceName, Default}, _From, State = #config{params = Params}) ->
	ParamName2 = iolist_to_binary([ServiceName, <<".">>, ParamName]),
	Result = maps:get(ParamName2, Params, Default),
	{reply, Result, State};

handle_call({use_port_offset, <<>>}, _From, State) ->
	{reply, undefined, State};
handle_call({use_port_offset, ServiceName, DefaultPort}, _From, State = #config{params = Params}) ->
	ParamName = iolist_to_binary([ServiceName, <<"_port_offset">>]),
	Port = maps:get(ParamName, Params, DefaultPort) ,
	Params2 = maps:put(ParamName, Port + 1, Params),
	State2 = State#config{params = Params2},
	{reply, Port, State2};

handle_call({add_catalog, CatName, CatFilename}, _From, Conf = #config{cat_path_search = CatPathSearch}) ->
	CatPathSearch2 = lists:keydelete(CatName, 1, CatPathSearch),
	Conf2 = Conf#config{cat_path_search = [{CatName, CatFilename} | CatPathSearch2]},
	ems_db:set_param(config_variables, Conf2),
	{reply, undefined, Conf2};

handle_call({remove_catalog, CatName}, _From, Conf = #config{cat_path_search = CatPathSearch}) ->
	CatPathSearch2 = lists:keydelete(CatName, 1, CatPathSearch),
	Conf2 = Conf#config{cat_path_search = CatPathSearch2},
	ems_db:set_param(config_variables, Conf2),
	{reply, undefined, Conf2}.


handle_info(_Msg, State) ->
   {noreply, State}.

handle_info(State) ->
   {noreply, State}.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    
    
%%====================================================================
%% Funções internas
%%====================================================================

% Returns the configuration file data
% Locais do arquivo: home do user (.erlangms/node@hostname.conf, .erlangms/emsbus.conf) ou na pasta priv/conf do barramento
-spec get_config_data() -> string() | {error, enofile_config}.
get_config_data() ->
	try
		ConfigFile = case init:get_argument(conf) of
								{ok, [[ConfigFileCommandLine]]} -> ConfigFileCommandLine;
								_ -> "emsbus.conf"
							end,
		Filename = select_config_file(ConfigFile, ?CONF_FILE_PATH_DEFAULT),
		case file:read_file(Filename) of 
			{ok, Arq} -> {ok, Arq, Filename};
			_ -> {error, enofile_config}
		end
	catch
		_:_ -> {error, enofile_config}
	end.


% Load the configuration file
load_config() ->
	case get_config_data() of
		{ok, ConfigData, Filename} ->
			ems_logger:format_info("ems_config loading configuration file \033[01;34m\"~s\"\033[0m.", [Filename]),
			case ems_util:json_decode_as_map(ConfigData) of
				{ok, Data} -> 
					case parse_config(Data, Filename) of
						{ok, Result} -> 
							Result;
						{error, Reason} -> 
							ems_logger:format_error("\nems_config cannot parse configuration file \033[01;34m\"~s\"\033[0m\033[00;33m. Reason: ~p. Data; ~p.\n", [Filename, Reason, Data]),
							erlang:error(einvalid_configuration)
					end;
				{error, Reason2} -> 
					ems_logger:format_error("\nems_config cannot decode configuration file \033[01;34m\"~s\"\033[0m\033[00;33m as json. Reason: ~p.\n", [Filename, Reason2]),
					erlang:error(einvalid_configuration)
			end;
		{error, enofile_config} ->
			ems_logger:format_error("ems_config cannnot read configuration file emsbus.conf, using default settings.\n"),
			erlang:error(einvalid_configuration)
	end.


get_cat_path_search_from_static_file_path_(CatPathSearch, []) -> CatPathSearch;
get_cat_path_search_from_static_file_path_(CatPathSearch, [{_, Path}|T]) ->
	ParseCatalogFun = fun(Filename, AccIn) -> 
		DirName = filename:dirname(Filename),
		LastDir = filename:basename(DirName),
		case LastDir =:= "assets" of
			true -> 
				DirName2 = string:slice(DirName, 1, length(DirName) - 8),
				LastDir2 = filename:basename(DirName2),
				case LastDir2 =:= "dist" of
					true -> 
						CatName = list_to_binary(filename:rootname(filename:basename(Filename))),
						[ {CatName, Filename} | AccIn ];
					false -> AccIn
				end;
			false ->
				case LastDir =:= "dist" of
					true -> 
						CatName = list_to_binary(filename:rootname(filename:basename(Filename))),
						[ {CatName, Filename} | AccIn ];
					false -> AccIn
				end
		end
	end,
	CatPathSearch2 = lists:reverse(filelib:fold_files(Path, "catalogo?.+\.json$", true, ParseCatalogFun, CatPathSearch)),
	get_cat_path_search_from_static_file_path_(CatPathSearch2, T).


get_cat_path_search_from_static_file_path(CatPathSearch, StaticFilePath) ->
	ems_logger:format_info("ems_config search catalogs in static_file_path..."),
	CatPathSearch2 = get_cat_path_search_from_static_file_path_(CatPathSearch, StaticFilePath),
	CatPathSearch2.

parse_cat_path_search_([], Result) -> Result;
parse_cat_path_search_([{CatName, CatFilename}|T], Result) -> 
	CatNameStr = binary_to_list(CatName),
	CatFilename2 = ems_util:parse_file_name_path(CatFilename, [], undefined),
	case file:read_file_info(CatFilename2, [{time, universal}]) of
		{ok, _} -> 
			ems_logger:format_info("ems_config loading catalog \033[00;32m\"~s\"\033[0m from \033[01;34m\"~s\"\033[0m.", [CatNameStr, CatFilename2]),
			parse_cat_path_search_(T, [{CatName, CatFilename2}|Result]);
		_ ->
			CatFilenameDir = filename:dirname(CatFilename2),
			CatFilenameZip = CatFilenameDir ++ ".zip",
			case file:read_file_info(CatFilenameZip, [{time, universal}]) of
				{ok, _} -> 
					CatTempDir = filename:join([?TEMP_PATH, "unzip_catalogs", CatNameStr]),
					zip:unzip(CatFilenameZip, [{cwd, CatTempDir}]),
					CatFilename3 = filename:join([CatTempDir, filename:basename(CatFilenameDir), filename:basename(CatFilename2)]),
					ems_logger:format_info("ems_config loading catalog \033[00;32m\"~s\"\033[0m\033 from \033[01;34m\"~s\"\033[0m.", [CatNameStr, CatFilenameZip]),
					parse_cat_path_search_(T, [{CatName, CatFilename3}|Result]);
				_ ->
					ems_logger:format_error("ems_config cannot load inexistent catalog \033[00;32m\"~s\"\033[0m\033[00;31m.", [CatFilename2]),
					parse_cat_path_search_(T, Result)
			end
	end.


-spec parse_cat_path_search(map(), list(string()), boolean()) -> list().
parse_cat_path_search(CatPathSearch, StaticFilePath, StaticFilePathProbing) ->
	case StaticFilePathProbing of
		true ->
			% Vamos descobrir mais catálogos a partir da lista static_file_path 
			CatPathSearch2 = get_cat_path_search_from_static_file_path(CatPathSearch, StaticFilePath);
		false ->
			CatPathSearch2 = CatPathSearch
	end,

	% Processar as entradas da lista. Pode ser um arquivo .zip
	CatPathSearch3 = parse_cat_path_search_(CatPathSearch2, []),

	% Adiciona o catálogo do barramento se necessário
	case lists:keymember(<<"ems-bus">>, 1, CatPathSearch3) orelse 
		 lists:keymember(<<"emsbus">>, 1, CatPathSearch3) of
			true -> CatPathSearch3;
			false -> [{<<"ems-bus">>, ?CATALOGO_ESB_PATH} | CatPathSearch3]
	end.


-spec parse_static_file_path(map()) -> list().
parse_static_file_path(StaticFilePathMap) ->
	StaticFilePathList = maps:to_list(StaticFilePathMap),
	StaticFilePathList2 = [{<<"login_path">>, list_to_binary(filename:join(?WWW_PATH, "login"))} | StaticFilePathList],
	StaticFilePathList3 = case lists:member(<<"www_path">>, StaticFilePathList2) of
						     true -> StaticFilePathList2;
							 false -> [{<<"www_path">>, list_to_binary(?WWW_PATH)} | StaticFilePathList2]
						  end,
	[{K, ems_util:remove_ult_backslash_url(binary_to_list(V))} || {K, V} <- StaticFilePathList3].
	

parse_datasources_([], _, _, Result) -> maps:from_list(Result);
parse_datasources_([DsName|T], Datasources, Conf, Result) ->
	M = maps:get(DsName, Datasources),
	Ds = ems_db:create_datasource_from_map(M, undefined, Conf),
	parse_datasources_(T, Datasources, Conf, [{DsName, Ds} | Result]).
								
parse_datasources(DatasourcesMap, Variables) ->
	parse_datasources_(maps:keys(DatasourcesMap), DatasourcesMap, Variables, []).
	
	
parse_tcp_allowed_address(undefined) -> all;
parse_tcp_allowed_address([<<"*.*.*.*">>]) -> all;
parse_tcp_allowed_address(V) -> V.

parse_http_headers(HttpHeaders, ShowDebugResponseHeaders, Hostname) ->
	parse_http_headers_(maps:to_list(HttpHeaders), ShowDebugResponseHeaders, Hostname, []).

parse_http_headers_([], ShowDebugResponseHeaders, Hostname, Result) ->
	HttpHeaders1 = maps:from_list(Result),
	case ShowDebugResponseHeaders of
		true -> HttpHeaders1#{<<"X-ems-server">> => ?SERVER_NAME,
							  <<"X-ems-node">> => ems_util:node_binary(),
							  <<"X-ems-hostname">> => Hostname};
		false -> HttpHeaders1
	end;
parse_http_headers_([{Key, Value} = Item|T], ShowDebugResponseHeaders, Hostname, Result) when is_binary(Value) ->
	case byte_size(Key) =< 100 andalso Value =/= undefined andalso Value =/= <<>> andalso byte_size(Value) =< 450 of
		true -> 
			parse_http_headers_(T, ShowDebugResponseHeaders, Hostname, [Item | Result]);
		false -> 
			erlang:error(einvalid_http_response_header)
	end;
parse_http_headers_([{Key, _} = Item|T], ShowDebugResponseHeaders, Hostname, Result) ->
	case byte_size(Key) =< 100 of
		true -> 
			parse_http_headers_(T, ShowDebugResponseHeaders, Hostname, [Item | Result]);
		false -> 
			erlang:error(einvalid_http_response_header)
	end.
	
parse_jar_path("") -> "";
parse_jar_path(<<>>) -> "";
parse_jar_path(undefined) -> "";
parse_jar_path(Path) ->	ems_util:replace_all_vars_and_custom_variables(Path, [{<<"PRIV_PATH">>, ?PRIV_PATH}]).

parse_java_home(<<>>) -> ems_util:get_java_home();
parse_java_home(undefined) -> ems_util:get_java_home();
parse_java_home(Path) -> 
	Path2 = binary_to_list(Path),
	Path3 = ems_util:replace_all_vars_and_custom_variables(Path2, [{<<"JAVA_HOME">>, ems_util:get_java_home()},
																	{<<"PRIV_PATH">>, ?PRIV_PATH}]),
	case Path3 =:= "" of
		true -> "";
		false ->
			case filelib:is_dir(Path3) of
				true -> 
					Path3;
				false -> 
					ems_logger:format_warn("ems_config detect inexistent java_home \033[01;34m\"~s\"\033[0m.", [Path3]),
					Path3
			end
	end.
	

parse_variables(V) when is_map(V) -> maps:to_list(V);
parse_variables(_) -> erlang:error(einvalid_variables).

get_p(ParamName, Map, DefaultValue) ->
	Result = maps:get(ParamName, Map, DefaultValue),
	case is_binary(Result) of
		true -> ems_util:replace_custom_variables_binary(Result);
		false -> Result
	end.

-spec parse_config(map(), string()) -> #config{}.
parse_config(Json, Filename) ->
	try
		{ok, InetHostname} = inet:gethostname(),
		
		put(parse_step, priv_path),
		PrivPath0 = binary_to_list(maps:get(<<"priv_path">>, Json, list_to_binary(ems_util:get_priv_dir_default()))),
		PrivPath = ems_util:parse_file_name_path(PrivPath0, [], undefined),
		
		ems_db:start(PrivPath),  %% precisa ser chamado neste ponto para salvar PrivPath em ems_db:set_param
		
		put(parse_step, www_path),
		WWWPath0 = binary_to_list(maps:get(<<"www_path">>, Json, filename:join(PrivPath, "www"))),		
		WWWPath = ems_util:parse_file_name_path(WWWPath0, [], undefined),
		ems_db:set_param(www_path, WWWPath),
		
		% este primeiro parâmetro é usado em todos os demais que é do tipo string
		put(parse_step, variables),
		CustomVariables = parse_variables(maps:get(<<"custom_variables">>, Json, #{})),
		ems_db:set_param(custom_variables, CustomVariables),

		put(parse_step, hostname),
		Hostname0 = ems_util:get_param_or_variable(<<"hostname">>, Json, <<>>),
		% permite setar o hostname no arquivo de configuração ou obter o nome da máquina pelo inet
		case Hostname0 of
			<<>> -> 
				Hostname = InetHostname,
				HostnameBin = list_to_binary(InetHostname);
			_ ->
				Hostname = binary_to_list(Hostname0),
				HostnameBin = Hostname0
		end,

		put(parse_step, tcp_listen_prefix_interface_names),
		TcpListenPrefixInterfaceNames = ems_util:binlist_to_list(get_p(<<"tcp_listen_prefix_interface_names">>, Json, ?TCP_LISTEN_PREFIX_INTERFACE_NAMES)),

		put(parse_step, tcp_listen_address),
		TcpListenAddress = ems_util:get_param_or_variable(<<"tcp_listen_address">>, Json, [<<"0.0.0.0">>]),

		put(parse_step, parse_tcp_listen_address),
		TcpListenAddress_t = ems_util:parse_tcp_listen_address(TcpListenAddress, TcpListenPrefixInterfaceNames),

		put(parse_step, get_tcp_listen_main_ip),
		{TcpListenMainIp, TcpListenMainIp_t} = get_tcp_listen_main_ip(TcpListenAddress_t),

		put(parse_step, show_debug_response_headers),
		ShowDebugResponseHeaders = ems_util:parse_bool(get_p(<<"show_debug_response_headers">>, Json, ?SHOW_DEBUG_RESPONSE_HEADERS)),

		put(parse_step, http_headers),
		HttpHeaders0 = maps:merge(?HTTP_HEADERS_DEFAULT, get_p(<<"http_headers">>, Json, #{})),

		put(parse_step, http_headers_options),
		HttpHeadersOptions0 = maps:merge(?HTTP_HEADERS_DEFAULT, get_p(<<"http_headers_options">>, Json, #{})),

		put(parse_step, parse_http_headers),
		HttpHeaders = parse_http_headers(HttpHeaders0, ShowDebugResponseHeaders, HostnameBin),

		put(parse_step, parse_http_headers_options),
		HttpHeadersOptions = parse_http_headers(HttpHeadersOptions0, ShowDebugResponseHeaders, HostnameBin),

		put(parse_step, rest_default_querystring),
		{Querystring, _QtdQuerystringRequired} = ems_util:parse_querystring_def(get_p(<<"rest_default_querystring">>, Json, []), []),

		put(parse_step, static_file_path_probing),
		StaticFilePathProbing = ems_util:parse_bool(get_p(<<"static_file_path_probing">>, Json, ?STATIC_FILE_PATH_PROBING)),

		put(parse_step, static_file_path),
		StaticFilePath = parse_static_file_path(get_p(<<"static_file_path">>, Json, #{})),
		StaticFilePathMap = maps:from_list(StaticFilePath),

		put(parse_step, catalog_path),
		CatPathSearch = parse_cat_path_search(maps:to_list(get_p(<<"catalog_path">>, Json, #{})), StaticFilePath, StaticFilePathProbing),

		put(parse_step, rest_base_url),
		case ems_util:get_param_or_variable(<<"rest_base_url">>, Json, <<>>) of
			<<>> ->	
				RestBaseUrlDefined = false,
				RestBaseUrl = iolist_to_binary([<<"http://"/utf8>>, TcpListenMainIp, <<":2301"/utf8>>]);
			RestBaseUrlValue -> 
				RestBaseUrlDefined = true,
				RestBaseUrl = ems_util:remove_ult_backslash_url_binary(RestBaseUrlValue)
		end,

		put(parse_step, rest_auth_url),
		case ems_util:get_param_or_variable(<<"rest_auth_url">>, Json, <<>>) of
		<<>> ->	
				case ems_util:get_param_or_variable(<<"rest_base_url">>, Json, <<>>) of		
					<<>> -> RestAuthUrl = iolist_to_binary([<<"http://"/utf8>>, TcpListenMainIp, <<":2301/authorize"/utf8>>]);
					_ -> RestAuthUrl = iolist_to_binary([RestBaseUrl, <<"/authorize"/utf8>>])
				end;
			RestAuthUrlValue -> RestAuthUrl = RestAuthUrlValue
		end,

		put(parse_step, rest_login_url),
		case ems_util:get_param_or_variable(<<"rest_login_url">>, Json, <<>>) of
			<<>> ->	RestLoginUrl = iolist_to_binary([RestBaseUrl, <<"/login/index.html"/utf8>>]);
			RestLoginUrlValue -> RestLoginUrl = ems_util:remove_ult_backslash_url_binary(RestLoginUrlValue)
		end,
 		put(parse_step, rest_url_mask),
		RestUrlMask = ems_util:parse_bool(get_p(<<"rest_url_mask">>, Json, false)),

		put(parse_step, rest_user),
		RestUser = binary_to_list(get_p(<<"rest_user">>, Json, <<"erlangms">>)),

		put(parse_step, rest_passwd),
		RestPasswd = binary_to_list(get_p(<<"rest_passwd">>, Json, <<"fEqNCco3Yq9h5ZUglD3CZJT4lBs=">>)),

		put(parse_step, host_alias),
		HostAlias = get_p(<<"host_alias">>, Json, #{<<"local">> => HostnameBin}),
		
		put(parse_step, debug),
		Debug = ems_util:parse_bool(get_p(<<"debug">>, Json, false)),

		put(parse_step, result_cache),
		ResultCache = ems_util:parse_result_cache(get_p(<<"result_cache">>, Json, ?TIMEOUT_DISPATCHER_CACHE)),

		put(parse_step, result_cache_shared),
		ResultCacheShared = ems_util:parse_bool(get_p(<<"result_cache_shared">>, Json, ?RESULT_CACHE_SHARED)),

		put(parse_step, result_cache_enabled),
		ResultCacheEnabled = ems_util:parse_bool(get_p(<<"result_cache_enabled">>, Json, true)),

		put(parse_step, tcp_allowed_address),
		TcpAllowedAddress = parse_tcp_allowed_address(get_p(<<"tcp_allowed_address">>, Json, all)),
		
		put(parse_step, http_max_content_length),
		HttpMaxContentLength = ems_util:parse_range(get_p(<<"http_max_content_length">>, Json, ?HTTP_MAX_CONTENT_LENGTH), 0, ?HTTP_MAX_CONTENT_LENGTH_BY_SERVICE),
		
		put(parse_step, authorization),
		Authorization = ems_util:parse_authorization_type(get_p(<<"authorization">>, Json, ?AUTHORIZATION_TYPE_DEFAULT)),

		put(parse_step, oauth2_with_check_constraint),
		OAuth2WithCheckConstraint = ems_util:parse_bool(get_p(<<"oauth2_with_check_constraint">>, Json, false)),
		
		put(parse_step, oauth2_refresh_token),
		OAuth2RefreshToken = ems_util:parse_range(get_p(<<"oauth2_refresh_token">>, Json, ?OAUTH2_DEFAULT_TOKEN_EXPIRY), 0, ?OAUTH2_MAX_TOKEN_EXPIRY),

		put(parse_step, auth_allow_user_inative_credentials),
		AuthAllowUserInativeCredentials = ems_util:parse_bool(get_p(<<"auth_allow_user_inative_credentials">>, Json, true)),

		put(parse_step, log_show_response),
		LogShowResponse = ems_util:parse_bool(get_p(<<"log_show_response">>, Json, ?LOG_SHOW_RESPONSE)),

		put(parse_step, log_show_payload),
		LogShowPayload = ems_util:parse_bool(get_p(<<"log_show_payload">>, Json, ?LOG_SHOW_PAYLOAD)),
		
		put(parse_step, log_show_response_max_length),
		LogShowResponseMaxLength = get_p(<<"log_show_response_max_length">>, Json, ?LOG_SHOW_RESPONSE_MAX_LENGTH),
		
		put(parse_step, log_show_payload_max_length),
		LogShowPayloadMaxLength = get_p(<<"log_show_payload_max_length">>, Json, ?LOG_SHOW_PAYLOAD_MAX_LENGTH),
		
		put(parse_step, log_file_checkpoint),
		LogFileCheckpoint = get_p(<<"log_file_checkpoint">>, Json, ?LOG_FILE_CHECKPOINT),
		
		put(parse_step, log_file_max_size),
		LogFileMaxSize = get_p(<<"log_file_max_size">>, Json, ?LOG_FILE_MAX_SIZE),
		
		put(parse_step, log_file_path),
		LogFilePath = get_p(<<"log_file_path">>, Json, ?LOG_FILE_PATH),

		put(parse_step, log_file_archive_path),
		LogFileArchivePath = get_p(<<"log_file_archive_path">>, Json, ?LOG_FILE_ARCHIVE_PATH),

		put(parse_step, log_show_odbc_pool_activity),
		LogShowOdbcPoolActivity = ems_util:parse_bool(get_p(<<"log_show_odbc_pool_activity">>, Json, ?LOG_SHOW_ODBC_POOL_ACTIVITY)),

		put(parse_step, log_show_data_loader_activity),
		LogShowDataLoaderActivity = ems_util:parse_bool(get_p(<<"log_show_data_loader_activity">>, Json, ?LOG_SHOW_DATA_LOADER_ACTIVITY)),

		put(parse_step, rest_environment),
		RestEnvironment = ems_util:get_param_or_variable(<<"rest_environment">>, Json, HostnameBin),
		
		put(parse_step, sufixo_email_institucional),
		SufixoEmailInstitucional = binary_to_list(get_p(<<"sufixo_email_institucional">>, Json, ?SUFIXO_EMAIL_INSTITUCIONAL)),
		
		put(parse_step, disable_services),
		DisableServices = get_p(<<"disable_services">>, Json, []),
		
		put(parse_step, enable_services),
		EnableServices = get_p(<<"enable_services">>, Json, []),
		
		put(parse_step, disable_services_owner),
		DisableServicesOwner = get_p(<<"disable_services_owner">>, Json, []),
		
		put(parse_step, enable_services_owner),
		EnableServicesOwner = get_p(<<"enable_services_owner">>, Json, []),
		
		put(parse_step, restricted_services_owner),
		RestrictedServicesOwner = get_p(<<"restricted_services_owner">>, Json, ?RESTRICTED_SERVICES_OWNER),
		
		put(parse_step, restricted_services_admin),
		RestrictedServicesAdmin = get_p(<<"restricted_services_admin">>, Json, ?RESTRICTED_SERVICES_ADMIN),
		
		put(parse_step, java_jar_path),
		JarPath = parse_jar_path(get_p(<<"java_jar_path">>, Json, ?JAVA_JAR_PATH)),

		put(parse_step, java_service_scan),
		JavaServiceScan = get_p(<<"java_service_scan">>, Json, ?JAVA_SERVICE_SCAN),

		put(parse_step, java_home),
		JavaHome = parse_java_home(get_p(<<"java_home">>, Json, <<>>)),

		put(parse_step, java_thread_pool),
		JavaThreadPool = ems_util:parse_range(get_p(<<"java_thread_pool">>, Json, 12), 1, 120),

		put(parse_step, java_service_user_notify),
		JavaServiceUserNotify = get_p(<<"java_service_user_notify">>, Json, undefined),
		case JavaServiceUserNotify =/= undefined andalso JavaServiceUserNotify =/= <<>> of
			true -> 
				{JavaServiceUserNotifyClass, _, JavaServiceUserNotifyFunction} = ems_util:parse_service_service(JavaServiceUserNotify),
				JavaServiceUserNotifyModule = list_to_atom(JavaServiceUserNotifyClass),
				JavaServiceUserNotifyClass2 = ems_util:replace(JavaServiceUserNotifyClass, "\\.", "_"),
				JavaServiceUserNotifyNode = list_to_atom(JavaServiceUserNotifyClass2 ++ "_node01@" ++ Hostname);
			false ->
				 JavaServiceUserNotifyModule = undefined,
				 JavaServiceUserNotifyNode = undefined,
				 JavaServiceUserNotifyFunction = undefined
		end,

		put(parse_step, java_service_user_notify_on_load_enabled),
		JavaServiceUserNotifyOnLoad = get_p(<<"java_service_user_notify_on_load_enabled">>, Json, false),

		put(parse_step, java_service_user_notify_on_update_enabled),
		JavaServiceUserNotifyOnUpdate = get_p(<<"java_service_user_notify_on_update_enabled">>, Json, true),

		put(parse_step, java_service_user_notify_full_sync_enabled),
		JavaServiceUserNotifyFullSyncEnabled = get_p(<<"java_service_user_notify_full_sync_enabled">>, Json, false),
		
		put(parse_step, java_service_user_notify_required_fields),
		JavaServiceUserNotifyRequiredFields = ems_util:binlist_to_atomlist(get_p(<<"java_service_user_notify_required_fields">>, Json, [<<"name">>, <<"login">>, <<"email">>, <<"cpf">>, <<"nome_mae">>])),

		put(parse_step, java_service_user_notify_source_types),
		JavaServiceUserNotifySourcesTypes = ems_util:binlist_to_atomlist(get_p(<<"java_service_user_notify_source_types">>, Json, ?CLIENT_DEFAULT_SCOPE_BIN)),

		put(parse_step, log_show_user_notify_activity),
		LogShowUserNotifyActivity = ems_util:parse_bool(get_p(<<"log_show_user_notify_activity">>, Json, true)),
		

		put(parse_step, smtp_passwd),
		SmtpPassword = binary_to_list(get_p(<<"smtp_passwd">>, Json, <<>>)),

		put(parse_step, smtp_from),
		SmtpFrom = binary_to_list(get_p(<<"smtp_from">>, Json, <<>>)),

		put(parse_step, smtp_mail),
		SmtpMail = binary_to_list(get_p(<<"smtp_mail">>, Json, <<>>)),

		put(parse_step, smtp_port),
		SmtpPort = get_p(<<"smtp_port">>, Json, 587),

		put(parse_step, ldap_url),
		LdapUrl = get_p(<<"ldap_url">>, Json, <<>>),

		put(parse_step, ldap_admin),
		LdapAdmin = list_to_binary(string:to_lower(binary_to_list(get_p(<<"ldap_admin">>, Json, <<>>)))),
				 
		put(parse_step, ldap_password_admin_crypto),
		LdapPasswdAdminCrypto = get_p(<<"ldap_password_admin_crypto">>, Json, <<>>),

		put(parse_step, ldap_base_search),
		LdapBaseSearch = get_p(<<"ldap_base_search">>, Json, <<>>),

		put(parse_step, ldap_password_admin),
		LdapPasswordAdmin0 = get_p(<<"ldap_password_admin">>, Json, <<>>),
		LdapPasswordAdmin = case LdapPasswdAdminCrypto of
								<<"SHA1">> -> LdapPasswordAdmin0;
								_ -> ems_util:criptografia_sha1(LdapPasswordAdmin0)
							end,

		put(parse_step, client_path_search),
		ClientPathSearch = select_config_file(<<"clients.json">>, get_p(<<"client_path_search">>, Json, ?CLIENT_PATH)),

		put(parse_step, user_path_search),
		UserPathSearch = select_config_file(<<"users.json">>, get_p(<<"user_path_search">>, Json, ?USER_PATH)),

		put(parse_step, dados_funcionais_path_search),
		DadosFuncionaisPathSearch = select_config_file(<<"user_dados_funcionais.json">>, get_p(<<"user_dados_funcionais_path">>, Json, ?USER_DADOS_FUNCIONAIS_PATH)),

		put(parse_step, user_perfil_path_search),
		UserPerfilPathSearch = select_config_file(<<"user_perfil.json">>, get_p(<<"user_perfil_path_search">>, Json, ?USER_PERFIL_PATH)),

		put(parse_step, user_permission_path_search),
		UserPermissionPathSearch = select_config_file(<<"user_permission.json">>, get_p(<<"user_permission_path_search">>, Json, ?USER_PERMISSION_PATH)),

		put(parse_step, user_endereco_path_search),
		UserEnderecoPathSearch = select_config_file(<<"user_endereco.json">>, get_p(<<"user_endereco_path_search">>, Json, ?USER_ENDERECO_PATH)),

		put(parse_step, user_telefone_path_search),
		UserTelefonePathSearch = select_config_file(<<"user_telefone.json">>, get_p(<<"user_telefone_path_search">>, Json, ?USER_TELEFONE_PATH)),

		put(parse_step, user_email_path_search),
		UserEmailPathSearch = select_config_file(<<"user_email.json">>, get_p(<<"user_email_path_search">>, Json, ?USER_EMAIL_PATH)),

		put(parse_step, ssl_cacertfile),
		SslCaCertfile = get_p(<<"ssl_cacertfile">>, Json, undefined),

		put(parse_step, ssl_certfile),
		SslCertfile = get_p(<<"ssl_certfile">>, Json, undefined),

		put(parse_step, ssl_keyfile),
		SslKeyfile = get_p(<<"ssl_keyfile">>, Json, undefined),

		put(parse_step, host_search),
		HostSearch = get_p(<<"host_search">>, Json, <<>>),	
		
		put(parse_step, node_search),
		NodeSearch = get_p(<<"node_search">>, Json, <<>>),		

		put(parse_step, new_config),
		Conf0 = #config{ 
				 cat_host_alias = HostAlias,
				 cat_host_search = HostSearch, 
				 cat_node_search = NodeSearch,
				 cat_path_search = CatPathSearch,
				 static_file_path = StaticFilePath,
				 static_file_path_map = StaticFilePathMap,
				 static_file_path_probing = StaticFilePathProbing,
				 cat_disable_services = DisableServices,
				 cat_enable_services = EnableServices,
				 cat_disable_services_owner = DisableServicesOwner,
				 cat_enable_services_owner = EnableServicesOwner,
				 cat_restricted_services_owner = RestrictedServicesOwner,
				 cat_restricted_services_admin = RestrictedServicesAdmin,
				 ems_hostname = HostnameBin,
				 ems_host = list_to_atom(Hostname),
				 ems_file_dest = Filename,
				 ems_debug = Debug,
				 ems_result_cache = ResultCache,
				 ems_result_cache_shared = ResultCacheShared,
				 ems_result_cache_enabled = ResultCacheEnabled,
				 show_debug_response_headers = ShowDebugResponseHeaders,
				 tcp_listen_address	= TcpListenAddress,
				 tcp_listen_address_t = TcpListenAddress_t,
				 tcp_listen_main_ip = TcpListenMainIp,
				 tcp_listen_main_ip_t = TcpListenMainIp_t,
				 tcp_listen_prefix_interface_names = TcpListenPrefixInterfaceNames,
				 tcp_allowed_address = TcpAllowedAddress,
				 http_max_content_length = HttpMaxContentLength,
				 http_headers = HttpHeaders,
				 http_headers_options = HttpHeadersOptions,
				 authorization = Authorization,
				 oauth2_with_check_constraint = OAuth2WithCheckConstraint,
				 oauth2_refresh_token = OAuth2RefreshToken,
				 auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials,
				 rest_base_url = RestBaseUrl, 
				 rest_auth_url = RestAuthUrl,
				 rest_login_url = RestLoginUrl,
				 rest_url_mask = RestUrlMask,
				 rest_environment = RestEnvironment,
				 rest_user = RestUser,
				 rest_passwd = RestPasswd,
				 rest_base_url_defined = RestBaseUrlDefined,
				 config_file = Filename,
				 params = Json,
				 client_path_search = ClientPathSearch,
				 user_path_search = UserPathSearch,
				 user_dados_funcionais_path_search = DadosFuncionaisPathSearch,
				 user_perfil_path_search = UserPerfilPathSearch,
				 user_permission_path_search = UserPermissionPathSearch,
				 user_endereco_path_search = UserEnderecoPathSearch, 
				 user_telefone_path_search = UserTelefonePathSearch, 
				 user_email_path_search	= UserEmailPathSearch, 
				 ssl_cacertfile = SslCaCertfile, 
				 ssl_certfile = SslCertfile, 
				 ssl_keyfile = SslKeyfile, 
				 sufixo_email_institucional = SufixoEmailInstitucional,
				 log_show_response = LogShowResponse,
				 log_show_payload = LogShowPayload,
				 log_show_response_max_length = LogShowResponseMaxLength,
				 log_show_payload_max_length = LogShowPayloadMaxLength,
				 log_file_checkpoint = LogFileCheckpoint,
				 log_file_max_size = LogFileMaxSize,
				 log_file_path = LogFilePath,
				 log_file_archive_path = LogFileArchivePath,
				 log_show_odbc_pool_activity = LogShowOdbcPoolActivity,
				 log_show_data_loader_activity = LogShowDataLoaderActivity,
				 log_show_user_notify_activity = LogShowUserNotifyActivity,
				 rest_default_querystring = Querystring,
				 java_jar_path = JarPath,
				 java_home = JavaHome,
				 java_thread_pool = JavaThreadPool,
				 java_service_scan = JavaServiceScan,
				 java_service_user_notify = JavaServiceUserNotify,
				 java_service_user_notify_module = JavaServiceUserNotifyModule,
				 java_service_user_notify_node = JavaServiceUserNotifyNode,
				 java_service_user_notify_function = JavaServiceUserNotifyFunction,
  				 java_service_user_notify_on_load_enabled = JavaServiceUserNotifyOnLoad,
 				 java_service_user_notify_on_update_enabled = JavaServiceUserNotifyOnUpdate,
				 java_service_user_notify_full_sync_enabled = JavaServiceUserNotifyFullSyncEnabled,
				 java_service_user_notify_required_fields = JavaServiceUserNotifyRequiredFields,
				 java_service_user_notify_source_types = JavaServiceUserNotifySourcesTypes,
				 smtp_passwd = SmtpPassword,
				 smtp_from = SmtpFrom,
				 smtp_mail = SmtpMail,
				 smtp_port = SmtpPort,
				 ldap_url = LdapUrl,
				 ldap_admin = LdapAdmin,
				 ldap_password_admin = LdapPasswordAdmin,
				 ldap_password_admin_crypto = <<"SHA1">>,
				 ldap_base_search = LdapBaseSearch,
				 custom_variables = CustomVariables,
				 www_path = WWWPath,
				 priv_path = PrivPath
			},

		put(parse_step, datasources),
		Datasources = parse_datasources(get_p(<<"datasources">>, Json, #{}), Conf0),

		put(parse_step, config_1),
		Conf1 = Conf0#config{ems_datasources = Datasources},

		ems_db:set_param(config_variables, Conf1),
		{ok, Conf1}
	catch
		_:Reason -> 
			ems_logger:format_error("ems_config cannot parse ~p in configuration file ~p. Reason: ~p.", [get(parse_step), Filename, Reason]),
			erlang:error(einvalid_configuration)
	end.

-spec select_config_file(binary() | string(), binary() | string()) -> {ok, string()} | {error, enofile_config}.
select_config_file(ConfigFile, ConfigFileDefault) ->
	ConfigFile2 = case is_binary(ConfigFile) of
					 true ->  binary_to_list(ConfigFile);
				  	 false -> ConfigFile
				  end,
	ConfigFileDefault2 = case is_binary(ConfigFileDefault) of
					 true ->  binary_to_list(ConfigFileDefault);
				  	 false -> ConfigFileDefault
				  end,
	HomePath = ems_util:get_home_dir(),
	Filename = filename:join([HomePath, ".erlangms", ConfigFile2]),
	case file:read_file(Filename) of 
		{ok, _Arq} -> 
			?DEBUG("ems_config checking if node file configuration ~p exist: Ok", [Filename]),
			Filename;
		_ -> 
			?DEBUG("ems_config checking if node file configuration ~p exist: No", [Filename]),
			Filename2 = lists:concat([HomePath, "/.erlangms/", ConfigFile2]),
			case file:read_file(Filename2) of 
				{ok, _Arq2} -> 
					?DEBUG("ems_config checking if file configuration ~p exist: Ok", [Filename2]),
					Filename2;
				_ -> 
					?DEBUG("ems_config checking if file configuration ~p exist: No", [Filename2]),
					case file:read_file(ConfigFileDefault2) of 
						{ok, _Arq3} -> 
							?DEBUG("ems_config checking if global file configuration ~p exist: Ok", [ConfigFileDefault2]),
							ConfigFileDefault2;
						_ -> 
							?DEBUG("ems_config checking if global file configuration ~p exist: No", [ConfigFileDefault2]),
							undefined
					end
			end
	end.


-spec get_tcp_listen_main_ip(list(tuple())) -> tuple().
get_tcp_listen_main_ip(TcpListenAddress_t) when length(TcpListenAddress_t) > 0 -> 
	Ip = lists:last(TcpListenAddress_t),
	{list_to_binary(inet:ntoa(Ip)), Ip};
get_tcp_listen_main_ip(_) -> {<<"127.0.0.1">>, {127,0,0,1}}.


	

