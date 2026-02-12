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
-include("include/ems_config_defaults.hrl").

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
		% Ativa modo debug se configurado no arquivo
		case Config#config.debug of
			true -> 
				ems_logger:mode_debug(true);
			_ -> ok
		end,
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
					erlang:error(einvalid_configuration),
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

	% Ignora parametro catalog_path para ems-bus informado no arquivo de configuracao
	CatPathSearch3 = lists:filter(fun({K, _}) -> 
		K =/= <<"ems-bus">> andalso K =/= <<"ems_bus">> andalso K =/= <<"emsbus">>
	end, CatPathSearch2),

	% Processar as entradas da lista. Pode ser um arquivo .zip
	CatPathSearch4 = parse_cat_path_search_(CatPathSearch3, []),

	% Adiciona o catálogo do barramento
	[{<<"ems-bus">>, ?CATALOGO_ESB_PATH} | CatPathSearch4].


-spec parse_static_file_path(map()) -> list().
parse_static_file_path(StaticFilePathMap) ->
	% Ignora parametro www_path informado no arquivo de configuracao
	StaticFilePathMap2 = maps:remove(<<"www_path">>, StaticFilePathMap),
	StaticFilePathList = maps:to_list(StaticFilePathMap2),

	% Adiciona o default
	WWWPathStr = ems_util:parse_file_name_path(filename:join(ems_db:get_param(priv_path), "www")),
	WWWPathBin = list_to_binary(WWWPathStr),
	StaticFilePathList2 = [{<<"www_path">>, WWWPathBin} | StaticFilePathList],
	ems_db:set_param(www_path, WWWPathStr),
	LoginPath = list_to_binary(filename:join(WWWPathStr, "login")),
	ems_db:set_param(login_path, LoginPath),
	StaticFilePathList3 = [{<<"login_path">>, LoginPath} | StaticFilePathList2],
	[{K, ems_util:parse_file_name_path(V)} || {K, V} <- StaticFilePathList3].
	

parse_datasources_([], _, _, Result) -> maps:from_list(Result);
parse_datasources_([DsName|T], Datasources, Conf, Result) ->
	M = maps:get(DsName, Datasources),
	Ds = ems_db:create_datasource_from_map(M, undefined, Conf, DsName),
	parse_datasources_(T, Datasources, Conf, [{DsName, Ds} | Result]).
								
parse_datasources(DatasourcesMap, Variables) ->
	parse_datasources_(maps:keys(DatasourcesMap), DatasourcesMap, Variables, []).
	
	
parse_tcp_allowed_address(undefined) -> all;
parse_tcp_allowed_address([<<"*.*.*.*">>]) -> all;
parse_tcp_allowed_address(V) -> V.

parse_user_agent_denied_list(undefined) -> [];
parse_user_agent_denied_list(V) -> V.




	

	

parse_variables(V) when is_map(V) -> maps:to_list(V);
parse_variables(_) -> erlang:error(einvalid_variables).

% Lê variáveis de ambiente do sistema operacional
% Retorna uma lista de tuplas {Nome, Valor}
get_env_variables() ->
	% Obtém todas as variáveis de ambiente
	EnvList = os:getenv(),
	% Converte para o formato esperado (lista de tuplas com binários)
	lists:filtermap(fun(S) ->
		Bin = list_to_binary(S),
		case binary:split(Bin, <<"=">>) of
			[K, V] -> {true, {K, V}};
			[K] -> {true, {K, <<>>}};
			_ -> false
		end
	end, EnvList).

% Mescla variáveis de ambiente com custom_variables
% Variáveis de ambiente têm precedência sobre custom_variables
merge_env_and_custom_variables(CustomVariables) ->
	EnvVariables = get_env_variables(),
	% Converte custom_variables para map para facilitar merge
	CustomVarsMap = maps:from_list(CustomVariables),
	EnvVarsMap = maps:from_list(EnvVariables),
	% Merge: env vars sobrescrevem custom vars
	MergedMap = maps:merge(CustomVarsMap, EnvVarsMap),
	maps:to_list(MergedMap).

get_p(ParamName, Map, DefaultValue) ->
	ResultDefault = maps:get(ParamName, ?CONFIG_DEFAULTS, DefaultValue),
	case maps:find(ParamName, Map) of
		{ok, Result} -> 
			IsEqual = (Result == ResultDefault),
			case IsEqual of
				true ->
					case ets:lookup(debug_ets, debug) of
						[{debug, true}] -> ems_logger:format_info("ems_config param ~s: ~p [DEFAULT]", [ParamName, ResultDefault]);
						_ -> ok
					end,
					case is_binary(ResultDefault) of
						true -> ems_util:replace_custom_variables_binary(ResultDefault);
						false -> ResultDefault
					end;
				false ->
					case ets:lookup(debug_ets, debug) of
						[{debug, true}] -> ems_logger:format_info("ems_config param ~s: ~p [CUSTOM]", [ParamName, Result]);
						_ -> ok
					end,
					case is_binary(Result) of
						true -> ems_util:replace_custom_variables_binary(Result);
						false -> Result
					end
			end;
		error ->
			case ets:lookup(debug_ets, debug) of
				[{debug, true}] -> ems_logger:format_info("ems_config param ~s: ~p [DEFAULT]", [ParamName, ResultDefault]);
				_ -> ok
			end,
			case is_binary(ResultDefault) of
				true -> ems_util:replace_custom_variables_binary(ResultDefault);
				false -> ResultDefault
			end
	end.

-spec parse_config(map(), string()) -> #config{}.
parse_config(Json, Filename) ->
	try
		{ok, InetHostname} = inet:gethostname(),
		


		
		put(parse_step, priv_path),
		PrivPath0 = ems_util:get_priv_dir_default(),
		PrivPath = ems_util:parse_file_name_path(PrivPath0, [], undefined),
		
		case filelib:is_dir(PrivPath) of
			true -> ems_logger:format_info("ems_config using priv_path \033[01;34m\"~s\"\033[0m.", [PrivPath]);
			false ->
				ems_logger:format_error("ems_config cannot found priv_path \033[01;34m\"~s\"\033[0m.", [PrivPath]),
				erlang:error(ecannot_found_priv_path)
		end,
		
		put(parse_step, database_path),
		DatabasePath0 = filename:join(PrivPath, "db"),
		DatabasePath = ems_util:parse_file_name_path(DatabasePath0, [], undefined),

		put(parse_step, database_path_check),
		case ems_util:ensure_dir_writable(DatabasePath) == ok of
			true -> ems_logger:format_info("ems_config using database_path \033[01;34m\"~s\"\033[0m.", [DatabasePath]);
			false ->
				ems_logger:format_error("ems_config database_path \033[01;34m\"~s\"\033[0m is read-only.", [DatabasePath]),
				erlang:error(ecannot_use_read_only_database_path)
		end,
		
		%% precisa ser chamado neste ponto para salvar PrivPath em ems_db:set_param
		put(parse_step, start_db),
		ems_db:start(PrivPath, DatabasePath),  
		
		% Instala o módulo de criptografia blowfish se necessário
		put(parse_step, blowfish_crypto_modpath),
		BlowfishCryptoModPath = ems_util:parse_file_name_path(get_p(<<"crypto_blowfish_module_path">>, Json, <<>>)),		

		put(parse_step, use_blowfish),
		UseBlowfish = BlowfishCryptoModPath =/= <<>>,
		case UseBlowfish of
			true ->
				put(parse_step, blowfish_crypto_modfilename),
				BlowfishCryptoModFileName = filename:basename(BlowfishCryptoModPath),
				
				put(parse_step, blowfish_crypto_module_ebin),
				BlowfishCryptoModuleEBin = filename:join(filename:join(ems_util:get_working_dir(), "ebin"), BlowfishCryptoModFileName),
				
				put(parse_step, blowfish_crypto_copy),
				
				ems_logger:format_info("ems_config initialize the blowfish encryption module."),
				case file:copy(BlowfishCryptoModPath, BlowfishCryptoModuleEBin) of
					{ok, _BytesCopied} ->
						ems_db:set_param(use_blowfish_crypto, true),
						ems_logger:format_info("ems_config blowfish encryption module initialized.");
					{error, ReasonBlowfish} ->
						ems_db:set_param(use_blowfish_crypto, false),
						ems_logger:format_error("ems_config failed to initialize blowfish encryption module ~p. Reason ~p.", [BlowfishCryptoModPath, ReasonBlowfish]),
						erlang:error(einvalid_crypto_blowfish_module_path)
				end;
			false -> 
				ems_db:set_param(use_blowfish_crypto, false),
				ok
		end,
		
		put(parse_step, static_file_path_probing),
		StaticFilePathProbing = ems_util:parse_bool(get_p(<<"static_file_path_probing">>, Json, ?STATIC_FILE_PATH_PROBING)),

		put(parse_step, static_file_path),
		StaticFilePath = parse_static_file_path(get_p(<<"static_file_path">>, Json, #{})),
		StaticFilePathMap = maps:from_list(StaticFilePath),

		put(parse_step, auth_default_scopes),
		AuthDefaultScopesAtom = ems_util:binlist_to_atomlist(get_p(<<"auth_default_scope">>, Json, ?AUTH_DEFAULT_SCOPE)),
		ems_db:set_param(auth_default_scope, AuthDefaultScopesAtom),

		put(parse_step, auth_password_check_between_scopes),
		AuthPasswordCheckBetweenScope = ems_util:parse_bool(get_p(<<"auth_password_check_between_scope">>, Json, true)),
		ems_db:set_param(auth_password_check_between_scope, AuthPasswordCheckBetweenScope),

		% este primeiro parâmetro é usado em todos os demais que é do tipo string
		put(parse_step, variables),
		CustomVariablesFromFile = parse_variables(get_p(<<"custom_variables">>, Json, #{})),
		% Mescla com variáveis de ambiente do sistema operacional
		% Variáveis de ambiente têm precedência
		CustomVariables = merge_env_and_custom_variables(CustomVariablesFromFile),
		ems_db:set_param(custom_variables, CustomVariables),

		put(parse_step, hostname),
		Hostname0 = ems_util:get_param_or_variable(<<"hostname">>, Json, get_p(<<"hostname">>, Json, <<>>)),
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
		TcpListenAddress = ems_util:get_param_or_variable(<<"tcp_listen_address">>, Json, get_p(<<"tcp_listen_address">>, Json, [<<"0.0.0.0">>])),

		put(parse_step, parse_tcp_listen_address),
		TcpListenAddress_t = ems_util:parse_tcp_listen_address(TcpListenAddress, TcpListenPrefixInterfaceNames),

		put(parse_step, get_tcp_listen_main_ip),
		{TcpListenMainIp, TcpListenMainIp_t} = get_tcp_listen_main_ip(TcpListenAddress_t),

		put(parse_step, debug),
		_ShowDebugResponseHeaders = ems_util:parse_bool(get_p(<<"debug">>, Json, ?SHOW_DEBUG_RESPONSE_HEADERS)),





		put(parse_step, rest_default_querystring),
		{Querystring, _QtdQuerystringRequired} = ems_util:parse_querystring_def(get_p(<<"rest_default_querystring">>, Json, []), []),

		put(parse_step, catalog_path),
		CatPathSearch = parse_cat_path_search(maps:to_list(get_p(<<"catalog_path">>, Json, #{})), StaticFilePath, StaticFilePathProbing),

		put(parse_step, rest_base_url),
		case ems_util:get_param_or_variable(<<"rest_base_url">>, Json, get_p(<<"rest_base_url">>, Json, <<>>)) of
			<<>> ->	
				RestBaseUrlDefined = false,
				RestBaseUrl = iolist_to_binary([<<"http://"/utf8>>, TcpListenMainIp, <<":2301"/utf8>>]);
			RestBaseUrlValue -> 
				RestBaseUrlDefined = true,
				RestBaseUrl = ems_util:remove_ult_backslash_url_binary(RestBaseUrlValue)
		end,

		put(parse_step, rest_auth_url),
		case ems_util:get_param_or_variable(<<"rest_auth_url">>, Json, get_p(<<"rest_auth_url">>, Json, <<>>)) of
			<<>> ->	
				case ems_util:get_param_or_variable(<<"rest_base_url">>, Json, get_p(<<"rest_base_url">>, Json, <<>>)) of		
					<<>> -> RestAuthUrl0 = iolist_to_binary([<<"http://"/utf8>>, TcpListenMainIp, <<":2301/authorize"/utf8>>]);
					_ -> RestAuthUrl0 = iolist_to_binary([RestBaseUrl, <<"/authorize"/utf8>>])
				end;
			RestAuthUrlValue -> RestAuthUrl0 = RestAuthUrlValue
		end,

		put(parse_step, rest_base_auth_url),
		RestBaseAuthUrlStr = re:replace(binary_to_list(RestAuthUrl0), "/authorize", "", [global, {return, list}]),
		RestBaseAuthUrl = list_to_binary(RestBaseAuthUrlStr),
		
		RestAuthUrl = list_to_binary(RestBaseAuthUrlStr ++ "/authorize"),

		put(parse_step, rest_login_url),
		case ems_util:get_param_or_variable(<<"rest_login_url">>, Json, get_p(<<"rest_login_url">>, Json, <<>>)) of
			<<>> ->	RestLoginUrl = RestBaseAuthUrlStr ++ "/login/index.html";
			RestLoginUrlValue -> RestLoginUrl = ems_util:remove_ult_backslash_url_binary(RestLoginUrlValue)
		end,

 		put(parse_step, rest_url_mask),
		RestUrlMask = ems_util:parse_bool(get_p(<<"rest_url_mask">>, Json, false)),

		put(parse_step, debug),
		RestUseHostInRedirect = ems_util:parse_bool(get_p(<<"rest_use_host_in_redirect">>, Json, false)),

		put(parse_step, rest_user),
		RestUser = binary_to_list(get_p(<<"rest_user">>, Json, <<"erlangms">>)),

		put(parse_step, rest_passwd),
		RestPasswd = binary_to_list(get_p(<<"rest_passwd">>, Json, ?DEFAULT_PASSWD)),

		put(parse_step, host_alias),
		HostAlias = get_p(<<"host_alias">>, Json, #{<<"local">> => HostnameBin}),
		
		put(parse_step, debug),
		Debug = ems_util:parse_bool(get_p(<<"debug">>, Json, false)),

		put(parse_step, result_cache),
		ResultCache = ems_util:parse_result_cache(get_p(<<"result_cache">>, Json, ?TIMEOUT_DISPATCHER_CACHE)),

		put(parse_step, result_cache_enabled),
		ResultCacheEnabledDefault = ?RESULT_CACHE_ENABLED_DEFAULT,
		ResultCacheEnabled = ems_util:parse_bool(get_p(<<"result_cache_enabled">>, Json, ResultCacheEnabledDefault)),

		put(parse_step, tcp_allowed_address),
		TcpAllowedAddress = parse_tcp_allowed_address(get_p(<<"tcp_allowed_address">>, Json, all)),

		put(parse_step, user_agent_denied_list),
		UserAgentDeniedList = parse_user_agent_denied_list(get_p(<<"user_agent_denied_list">>, Json, [])),
		ems_db:set_param(user_agent_denied_list, UserAgentDeniedList),
		
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

		put(parse_step, log_show_response_header),
		LogShowResponseHeader = ems_util:parse_bool(get_p(<<"log_show_response_header">>, Json, ?LOG_SHOW_RESPONSE_HEADER)),

		put(parse_step, log_show_payload),
		LogShowPayload = ems_util:parse_bool(get_p(<<"log_show_payload">>, Json, ?LOG_SHOW_PAYLOAD)),
		
		put(parse_step, log_show_content_static_file),
		LogShowPayloadStaticFile = ems_util:parse_bool(get_p(<<"log_show_content_static_file">>, Json, ?LOG_SHOW_CONTENT_STATIC_FILE)),

		put(parse_step, log_show_response_max_length),
		LogShowResponseMaxLength = get_p(<<"log_show_response_max_length">>, Json, ?LOG_SHOW_RESPONSE_MAX_LENGTH),
		
		put(parse_step, log_show_payload_max_length),
		LogShowPayloadMaxLength = get_p(<<"log_show_payload_max_length">>, Json, ?LOG_SHOW_PAYLOAD_MAX_LENGTH),
		
		put(parse_step, max_connection_by_pool),
		MaxConnectionByPool = ems_util:parse_range(get_p(<<"max_connection_by_pool">>, Json, ?MAX_CONNECTION_IDDLE_BY_POOL), 1, 1000),
		ems_db:set_param(max_connection_by_pool, MaxConnectionByPool),

		put(parse_step, log_show_odbc_pool_activity),
		LogShowOdbcPoolActivity = ems_util:parse_bool(get_p(<<"log_show_odbc_pool_activity">>, Json, ?LOG_SHOW_ODBC_POOL_ACTIVITY)),

		put(parse_step, log_show_data_loader_activity),
		LogShowDataLoaderActivity = ems_util:parse_bool(get_p(<<"log_show_data_loader_activity">>, Json, ?LOG_SHOW_DATA_LOADER_ACTIVITY)),

		put(parse_step, rest_environment),
		RestEnvironment = ems_util:get_param_or_variable(<<"rest_environment">>, Json, get_p(<<"rest_environment">>, Json, HostnameBin)),
		
		put(parse_step, sufixo_email_institucional),
		SufixoEmailInstitucional0 = binary_to_list(get_p(<<"sufixo_email_institucional">>, Json, ?SUFIXO_EMAIL_INSTITUCIONAL)),
		case string:trim(SufixoEmailInstitucional0) of
			"" -> SufixoEmailInstitucional = ?SUFIXO_EMAIL_INSTITUCIONAL;
			SufixoEmailInstitucionalValue -> SufixoEmailInstitucional = string:to_lower(SufixoEmailInstitucionalValue)
		end,
		ems_db:set_param(sufixo_email_institucional, SufixoEmailInstitucional),
		
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
		LdapBaseSearch = binary_to_list(get_p(<<"ldap_base_search">>, Json, <<>>)),

		put(parse_step, rate_limit_interno),
		RateLimitInterno = get_p(<<"rate_limit_interno">>, Json, 50),

		put(parse_step, rate_limit_externo),
		RateLimitExterno = get_p(<<"rate_limit_externo">>, Json, 15),

		put(parse_step, rate_limit_cidr_interno),
		RateLimitCidrInterno = ems_util:parse_cidr(get_p(<<"rate_limit_cidr_interno">>, Json, <<"164.41.0.0/16">>)),

		put(parse_step, force_https),
		ForceHttps = ems_util:parse_bool(get_p(<<"force_https">>, Json, false)),

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
		HostSearch = maps:get(<<"host_search">>, ?CONFIG_DEFAULTS),
		
		put(parse_step, node_search),
		NodeSearch = maps:get(<<"node_search">>, ?CONFIG_DEFAULTS),


		WWWPath = ems_db:get_param(www_path),
		
		put(parse_step, oauth2_resource_owner_find_permission_with_cpf),
		OAuth2ResourceOwnerFindPermissionWithCPF = ems_util:parse_bool(get_p(<<"oauth2_resource_owner_find_permission_with_cpf">>, Json, true)),
		ems_db:set_param(oauth2_resource_owner_find_permission_with_cpf, OAuth2ResourceOwnerFindPermissionWithCPF),
		
		put(parse_step, oauth2_resource_owner_fields),
		OAuth2ResourceOwnerFields = get_p(<<"oauth2_resource_owner_fields">>, Json, ?OAUTH2_RESOURCE_OWNER_FIELDS),
		ems_db:set_param(oauth2_resource_owner_fields, OAuth2ResourceOwnerFields),

		put(parse_step, oauth2_jwt_secret),
		OAuth2JwtSecret = list_to_binary(get_p(<<"oauth2_jwt_secret">>, Json, "secret_default_change_me")),
		ems_db:set_param(oauth2_jwt_secret, OAuth2JwtSecret),


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
				 debug = Debug,
				 ems_result_cache = ResultCache,
				 ems_result_cache_enabled = ResultCacheEnabled,
				 tcp_listen_address	= TcpListenAddress,
				 tcp_listen_address_t = TcpListenAddress_t,
				 tcp_listen_main_ip = TcpListenMainIp,
				 tcp_listen_main_ip_t = TcpListenMainIp_t,
				 tcp_listen_prefix_interface_names = TcpListenPrefixInterfaceNames,
				 tcp_allowed_address = TcpAllowedAddress,
				 http_max_content_length = HttpMaxContentLength,

				 authorization = Authorization,
				 oauth2_with_check_constraint = OAuth2WithCheckConstraint,
				 oauth2_refresh_token = OAuth2RefreshToken,
				 auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials,
				 rest_base_url = RestBaseUrl, 
				 rest_base_auth_url = RestBaseAuthUrl,
				 rest_auth_url = RestAuthUrl,
				 rest_login_url = RestLoginUrl,
				 rest_url_mask = RestUrlMask,
				 rest_environment = RestEnvironment,
				 rest_user = RestUser,
				 rest_passwd = RestPasswd,
				 rest_base_url_defined = RestBaseUrlDefined,
				 rest_use_host_in_redirect = RestUseHostInRedirect,
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
				 oauth2_jwt_secret = OAuth2JwtSecret,
				 log_show_response = LogShowResponse,
				 log_show_response_header = LogShowResponseHeader,
				 log_show_payload = LogShowPayload,
				 log_show_content_static_file = LogShowPayloadStaticFile,
				 log_show_response_max_length = LogShowResponseMaxLength,
				 log_show_payload_max_length = LogShowPayloadMaxLength,
				 log_show_odbc_pool_activity = LogShowOdbcPoolActivity,
				 log_show_data_loader_activity = LogShowDataLoaderActivity,
				 rest_default_querystring = Querystring,
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
				 rate_limit_interno = RateLimitInterno,
				 rate_limit_externo = RateLimitExterno,
				 rate_limit_cidr_interno = RateLimitCidrInterno,
				 www_path = WWWPath,
				 database_path = DatabasePath,
				 priv_path = PrivPath,
				 auth_default_scope = AuthDefaultScopesAtom,
				 auth_password_check_between_scope = AuthPasswordCheckBetweenScope,
				 crypto_blowfish_module_path = BlowfishCryptoModPath,
				 oauth2_resource_owner_find_permission_with_cpf = OAuth2ResourceOwnerFindPermissionWithCPF,
 				 oauth2_resource_owner_fields = OAuth2ResourceOwnerFields,
				 user_agent_denied_list = UserAgentDeniedList,
				 force_https = ForceHttps
				 
			},

		put(parse_step, datasources),
		Datasources = parse_datasources(get_p(<<"datasources">>, Json, #{}), Conf0),

		put(parse_step, config_1),
		Conf1 = Conf0#config{ems_datasources = Datasources},

		ems_db:set_param(config_variables, Conf1),
		{ok, Conf1}
	catch
		_:Reason -> 
			ems_logger:format_error("ems_config cannot parse ~p in configuration file \033[01;34m~p\033[0m. Reason: ~p.", [get(parse_step), Filename, Reason]),
			io:format("\033[06;31m~p\033[0m\n", [Json]),
			erlang:error(Reason)
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


	

