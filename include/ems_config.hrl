%%********************************************************************
%% @title Arquivo de configuração ErlangMS
%% @version 1.0.0
%% @doc Arquivo com configurações gerais de funcionamento de ErlangMS.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-define(DEBUG(Msg), ems_logger:debug(Msg)).
-define(DEBUG(Msg, Params), ems_logger:debug(Msg, Params)).


%-define(JSON_LIB, jiffy).
-define(JSON_LIB, native).

-define(UTF8_STRING(Text), ems_util:utf8_string_linux(Text)).

% Nome do servidor
-define(SERVER_NAME, ems_util:server_name()).

-define(PRIV_PATH_DEFAULT, ems_util:get_priv_dir_default()).

% Caminho do diretório privado
-define(PRIV_PATH, ems_util:get_priv_dir()).

% Caminho do diretório de trabalho
-define(WORKING_PATH, ems_util:get_working_dir()).

% Caminho do diretório privado
-define(TEMP_PATH, filename:join(?PRIV_PATH, "tmp")).

% Caminho do catálogo de serviços
-define(CONF_PATH_DEFAULT, filename:join(?PRIV_PATH_DEFAULT, "conf")).

% Caminho do catálogo de serviços
-define(CONF_PATH, filename:join(?PRIV_PATH, "conf")).

% Caminho do favicon
-define(FAVICON_PATH, filename:join(?PRIV_PATH, "favicon.ico")).

% Caminho do catálogo de serviços
-define(CATALOGO_PATH, filename:join(?PRIV_PATH, "catalog")).

% Caminho do catálogo de serviços
-define(CATALOGO_ESB_PATH, filename:join(?CATALOGO_PATH, "catalog.json")).

% Caminho da pasta de databases
-define(DATABASE_PATH, ems_db:get_param(database_path)).

% Caminho do arquivo de configuração padrão (Pode ser incluído também na pasta ~/.erlangms do usuário)
-define(CONF_FILE_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "emsbus.conf")).

% Caminho do arquivo de configuração padrão (Pode ser incluído também na pasta ~/.erlangms do usuário)
-define(CONF_FILE_PATH, filename:join(?CONF_PATH, "emsbus.conf")).

% Caminho inicial para a pasta www
-define(WWW_PATH, ems_util:get_www_path()).

% Sonda a lista static_file_path para localizar contratos de serviços
-define(STATIC_FILE_PATH_PROBING, false).

% Caminho do arquivo de clientes
-define(CLIENT_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "clients.json")).
-define(CLIENT_PATH, ems_db:get_param(client_path, ?CLIENT_PATH_DEFAULT)).

% Caminho do arquivo de usuários
-define(USER_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "users.json")).
-define(USER_PATH, ems_db:get_param(user_path, ?USER_PATH_DEFAULT)).

% Caminho do arquivo de dados funcionais dos usuários
-define(USER_DADOS_FUNCIONAIS_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "user_dados_funcionais.json")).
-define(USER_DADOS_FUNCIONAIS_PATH, ems_db:get_param(user_dados_funcionais_path, ?USER_DADOS_FUNCIONAIS_PATH_DEFAULT)).

% Caminho do arquivo de dados funcionais dos usuários
-define(USER_EMAIL_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "user_email.json")).
-define(USER_EMAIL_PATH, ems_db:get_param(user_email_path, ?USER_EMAIL_PATH_DEFAULT)).

% Caminho do arquivo de perfis dos usuários
-define(USER_PERFIL_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "user_perfil.json")).
-define(USER_PERFIL_PATH, ems_db:get_param(user_perfil_path, ?USER_PERFIL_PATH_DEFAULT)).

% Caminho do arquivo de permissões dos usuários
-define(USER_PERMISSION_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "user_permission.json")).
-define(USER_PERMISSION_PATH, ems_db:get_param(user_permission_path, ?USER_PERMISSION_PATH_DEFAULT)).

% Caminho do arquivo de endereços dos usuários
-define(USER_ENDERECO_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "user_endereco.json")).
-define(USER_ENDERECO_PATH, ems_db:get_param(user_endereco_path, ?USER_ENDERECO_PATH_DEFAULT)).

% Caminho do arquivo de telefones dos usuários
-define(USER_TELEFONE_PATH_DEFAULT, filename:join(?CONF_PATH_DEFAULT, "user_telefone.json")).
-define(USER_TELEFONE_PATH, ems_db:get_param(user_telefone_path, ?USER_TELEFONE_PATH_DEFAULT)).

% Caminho inicial para os arquivos estáticos
-define(WEBAPPS_PATH, filename:join(?PRIV_PATH, "www")).

% Caminho inicial para os arquivos de carga de dados em formato CSV
-define(CSV_FILE_PATH, filename:join(?PRIV_PATH, "csv")).

% Caminho dos certificados ssl
-define(SSL_PATH, filename:join(?PRIV_PATH, "ssl")).

% Mostra no log payload e response
-define(LOG_SHOW_RESPONSE, false).
-define(LOG_SHOW_RESPONSE_HEADER, true).
-define(LOG_SHOW_PAYLOAD, false).
-define(LOG_SHOW_CONTENT_STATIC_FILE, false).

-define(RESTRICTED_SERVICES_OWNER, [ <<"netadm">>, <<"logger">>, <<"auth">> ]).
-define(RESTRICTED_SERVICES_ADMIN, [ <<"erlangms">> ]).

% Define o tamanho máximo default que pode ser impresso no log do payload e response para depuração
-define(LOG_SHOW_PAYLOAD_MAX_LENGTH, 120).
-define(LOG_SHOW_RESPONSE_MAX_LENGTH, 120).

% Define se mostra as atividades do pool de conexão no log para depuração
-define(LOG_SHOW_ODBC_POOL_ACTIVITY, false).

% Define se mostra as atividades dos data loaders
-define(LOG_SHOW_DATA_LOADER_ACTIVITY, true).

% Mostra cabeçalhos de depuração
-define(SHOW_DEBUG_RESPONSE_HEADERS, false).

% Quanto tempo o dispatcher aguardar um serviço
-define(SERVICE_TIMEOUT, 60000). 		 % 1 minuto é o tempo padrão que o dispatcher aguarda um serviço executar
-define(SERVICE_MIN_TIMEOUT, 30000). 	 % 30 segundos é o tempo mínimo que o dispatcher aguarda um serviço executar
-define(SERVICE_MAX_TIMEOUT, 120000). 	 % 2 minutos é o tempo máximo que o dispatcher aguarda um serviço executar
-define(SERVICE_MIN_EXPIRE_MINUTE, 0).	 % 0 minutos é o tempo mínimo que o dispatcher aguarda um serviço expirar
-define(SERVICE_MAX_EXPIRE_MINUTE, 1440). % 24 horas é o tempo máximo que o dispatcher aguarda um serviço expirar

% Range de tempo para iniciar processos kernel
-define(START_TIMEOUT, 1000).
-define(START_TIMEOUT_MIN, 0).
-define(START_TIMEOUT_MAX, 1800000).  % 30 minutos é o tempo máximo que o dispatcher aguarda um processo kernel iniciar

% Caminho do utilitário que importa dados csv para um banco sqlite
-define(CSV2SQLITE_PATH, filename:join([?PRIV_PATH, "scripts", "csv2sqlite.py"])). 

% Limits of API query
-define(MAX_LIMIT_API_QUERY, 99999999).
-define(MAX_OFFSET_API_QUERY, 99999).
-define(MAX_TIME_ODBC_QUERY, 960000).
-define(MAX_ID_RECORD_QUERY, 9999999999).  

% Timeout in ms to expire cache of get request (ems_dispatcher_cache)
-define(TIMEOUT_DISPATCHER_CACHE, 30000).

% Number of datasource entries by odbc connection pool in iddle
-define(MAX_CONNECTION_IDDLE_BY_POOL, 4).

% Timeout to check odbc connection
-define(CHECK_VALID_CONNECTION_TIMEOUT, 120000). % 2 minutos
-define(MAX_CLOSE_IDLE_CONNECTION_TIMEOUT, 3600000). % 1h
-define(CLOSE_IDLE_CONNECTION_TIMEOUT, 3600000). % 1h


% Define the default checkpoint to ems_data_loader and ems_json_loader
-define(DATA_LOADER_UPDATE_CHECKPOINT, 90000).

%Define the checkpoint to update permission for ems_user_permission_l
% HTTP access control (CORS) headers
-define(ACCESS_CONTROL_ALLOW_HEADERS, <<"Accept, Accept-Language, Content-Language, Content-Type, X-ACCESS_TOKEN, X-CSRF-Token, Access-Control-Allow-Origin, Authorization, Origin, x-requested-with, Content-Range, Content-Disposition, Content-Description">>).
-define(ACCESS_CONTROL_MAX_AGE_DEFAULT_CHROME, <<"7200">>).  % 2 hours - Chrome maximum
-define(ACCESS_CONTROL_MAX_AGE, ?ACCESS_CONTROL_MAX_AGE_DEFAULT_CHROME).
-define(ACCESS_CONTROL_ALLOW_ORIGIN, <<"*">>).
-define(ACCESS_CONTROL_ALLOW_METHODS, <<"GET, POST, PUT, DELETE, OPTIONS, HEAD">>).
-define(ACCESS_CONTROL_EXPOSE_HEADERS, <<"Cache-Control, Content-Language, Content-Type, Expires, Last-Modified, Content-Length">>).

% CORS domain suffix (default: .unb.br)
% Requests from domains ending with this suffix will be allowed
-define(CORS_DOMAIN, <<".unb.br">>).

% Oauth2
-define(OAUTH2_DEFAULT_AUTHORIZATION, oauth2).
-define(AUTHORIZATION_TYPE_DEFAULT, <<"oauth2">>).

-define(OAUTH2_RESOURCE_OWNER_FIELDS, [ <<"id">>, <<"remap_user_id">>, <<"codigo">>, <<"login">>, <<"name">>, <<"email">>, 
										<<"type">>, <<"subtype">>,  <<"active">>, <<"cpf">>, <<"lista_perfil">>, 
										<<"lista_permission">>, <<"lista_perfil_permission">> ]).

-define(DEFAULT_PASSWD, <<"fEqNCco3Yq9h5ZUglD3CZJT4lBs=">>).

% Mensagens de saída json comuns
-define(CONTENT_TYPE_JSON, <<"application/json">>).

-define(CACHE_CONTROL_NO_CACHE, <<"no-store, no-cache, must-revalidate, private"/utf8>>).

-define(OK_JSON, <<"{\"ok\": true}"/utf8>>).
-define(ENOENT_JSON, <<"{\"error\": \"enoent\"}"/utf8>>).
-define(ENOENT_SERVICE_CONTRACT_JSON, <<"{\"error\": \"enoent_service_contract\"}"/utf8>>).
-define(EUNAVAILABLE_SERVICE_JSON, <<"{\"error\": \"eunavailable_service\"}"/utf8>>).
-define(EINVALID_HTTP_REQUEST, <<"{\"error\": \"einvalid_request\"}"/utf8>>).
-define(ETIMEOUT_SERVICE, <<"{\"error\": \"etimeout_service\"}"/utf8>>).
-define(EMPTY_LIST_JSON, <<"[]"/utf8>>).
-define(ACCESS_DENIED_JSON, <<"{\"error\": \"access_denied\"}"/utf8>>).
-define(EINVALID_DATA_LOADER, <<"{\"error\": \"einvalid_data_loader\"}"/utf8>>).
-define(HOST_DENIED_JSON, <<"{\"error\": \"host_denied\"}"/utf8>>).
-define(EFORBIDDEN_JSON, <<"{\"error\": \"eforbidden\"}"/utf8>>).
-define(ERATE_LIMIT_EXCEEDED, <<"{\"error\": \"erate_limit_exceeded\"}"/utf8>>).
-define(OAUTH2_DEFAULT_TOKEN_EXPIRY, 3600).  % 1 hour
-define(OAUTH2_MAX_TOKEN_EXPIRY, 2592000).   % 30 days

-define(HTTP_HEADERS_DEFAULT, #{<<"server">> => ?SERVER_NAME,
							    <<"cache-control">> => ?CACHE_CONTROL_NO_CACHE,
							    <<"x-frame-options">> => <<"DENY">>,
							    <<"x-content-type-options">> => <<"nosniff">>,
							    <<"access-control-max-age">> => ?ACCESS_CONTROL_MAX_AGE,
							    <<"access-control-allow-headers">> => ?ACCESS_CONTROL_ALLOW_HEADERS,
							    <<"access-control-allow-methods">> => ?ACCESS_CONTROL_ALLOW_METHODS,
							    <<"access-control-expose-headers">> => ?ACCESS_CONTROL_EXPOSE_HEADERS,
							    <<"strict-transport-security">> => <<"max-age=31536000; includeSubDomains; preload">>,
							    <<"content-security-policy">> => <<"default-src 'self'; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self';">>,
							    <<"referrer-policy">> => <<"strict-origin-when-cross-origin">>
							  }).

% LDAP
-define(LDAP_SERVER_PORT, 2389).
-define(LDAP_MAX_CONNECTIONS, 100000).
-define(LDAP_MAX_SIZE_PACKET, 20000).
-define(LDAP_SUCCESS, 0).
-define(LDAP_INAPPRORIATE_AUTHENCATION, 48).
-define(LDAP_INVALID_CREDENTIALS, 49).
-define(LDAP_INSUFFICIENT_ACCESS_RIGHTS, 50).  
-define(LDAP_NO_SUCH_OBJECT, 32).  
-define(LDAP_INAPPROPRIATE_MATCHING, 18).  
-define(LDAP_NO_SUCH_ATTRIBUTE, 16).  


% HTTP
-define(HTTP_SERVER_PORT, 2381).
-define(HTTP_MAX_CONNECTIONS, 1024).
-define(HTTP_MAX_CONTENT_LENGTH, 2097152).  % Limite default do conteúdo do payload é de 2MB
-define(HTTP_MAX_CONTENT_LENGTH_BY_SERVICE, 1048576000).  % Permite enviar até 1G se especificado no contrato de serviço
-define(HTTP_MAX_URI_LENGTH, 16384).  % Limite máximo de 16KB para URI (previne ataques de DoS)
-define(HTTP_MAX_QUERYSTRING_LIMIT, 100).  % Limite máximo de 100 parâmetros na querystring (previne ataques de DoS)
-define(HTTP_TARPIT_DELAY, 30000).  % Delay de 30 segundos para requisições maliciosas (Tarpit)
-define(HTTP_URL_DENY_LIST_RE, [
    "\\.php$", "\\.jsp$", "\\.asp$", "\\.aspx$", "\\.exe$", "\\.pl$", "\\.cgi$", "\\.sh$", "\\.yaml$", "\\.env$"
]).
-define(RATE_LIMIT_CIDR_INTERNO, <<"164.41.0.0/16">>).
-define(RATE_LIMIT_INTERNO, 50).
-define(RATE_LIMIT_EXTERNO, 15).
-define(RESULT_CACHE_ENABLED_DEFAULT, true).
-define(HTTP_SERVER_HEADER, <<"Okatsu">>).  % Obfuscated Server header
-define(HTTP_MAX_CACHE_CONTROL_AGE, 86400).   % 1 day in seconds
-define(HTTP_HEADERS_PROHIBITED_LIST, [
    <<"x-powered-by">>, 
    <<"x-aspnet-version">>, 
    <<"public-key-pins">>,              % HPKP is deprecated and dangerous
    <<"x-runtime">>, 
    <<"x-version">>,
    <<"pragma">>                        % Deprecated
]).

% TCP
-define(TCP_PORT_MIN, 1024).
-define(TCP_PORT_MAX, 99999).
-define(TCP_LISTEN_PREFIX_INTERFACE_NAMES, [<<"lo">>, <<"enp">>, <<"eth">>, <<"wl">>, <<"eno">>, <<"ens">>]).

-define(PERSIST_TOKEN_SGBD_ENABLED, true).

-define(SUFIXO_EMAIL_INSTITUCIONAL, <<"@unb.br">>).

% Result cache
-define(RESULT_CACHE_MAX_SIZE_ENTRY, 5242880). % 5MB
-define(MAX_RESULT_CACHE, 31536000000). % 1 year in ms

%% Cache limits (ems_cache module)
-define(CACHE_MAX_OBJECT_SIZE, 5242880).      % 5MB max per object
-define(CACHE_MAX_TTL, 31536000000).          % 1 year
-define(CACHE_MAX_ENTRIES, 1000).            % 1000 entries max per cache
-define(USER_CACHE_POSITIVE_TTL, 15000).      % 15 segundos
-define(USER_CACHE_NEGATIVE_TTL, 5000).       % 5 segundos
-define(USER_RESOURCE_OWNER_CACHE_TTL, 300000). % 5 minutos

-define(AUTH_DEFAULT_SCOPE, [<<"user_db">>, <<"user_fs">>]).

-define(CLIENT_DEFAULT_SCOPE, ems_util:get_auth_default_scope()).

% Código de cores
-define(WARN_MESSAGE,   		<<"WARN ">>).
-define(INFO_MESSAGE,   		<<"INFO ">>).
-define(ERROR_MESSAGE,  		<<"ERROR ">>).
-define(DEBUG_MESSAGE,  		<<"DEBUG ">>).
-define(ALERT_MESSAGE,  		<<"INFO ">>).
-define(LIGHT_GREEN_COLOR,    	<<>>).
-define(GREEN_COLOR, 			<<>>).
-define(TAB_GREEN_COLOR, 		<<"\n\t">>).
-define(SPACE_GREEN_COLOR, 		<<" ">>).
-define(WHITE_COLOR, 			<<>>).
-define(WHITE_SPACE_COLOR, 		<<" ">>).
-define(WHITE_BRK_COLOR,		<<"\n">>).
-define(WHITE_PARAM_COLOR,		<<": ">>).
-define(RED_COLOR, 				<<>>).
-define(WARN_COLOR, 			<<>>).
-define(DEBUG_COLOR, 			<<>>).
-define(BLUE_COLOR, 			<<>>).
-define(BLUE_SPACE_COLOR, 		<<" ">>).

%  Definição para o arquivo de configuração
-record(config, {cat_host_alias :: map(),							%% Lista (Chave-Valor) com os names alternativos para os hosts. Ex.: ["negocio01", "192.168.0.103", "negocio02", "puebla"]
				 cat_host_search,									%% Lista de hosts para pesquisar os serviços
				 cat_node_search,									%% Lista de nodes para pesquisar os serviços
				 cat_path_search :: list(tuple()),					%% Lista de tuplas com caminhos alternativos para catálogos
				 cat_disable_services :: list(binary()),			%% Lista de serviços para desativar
				 cat_enable_services :: list(binary()),				%% Lista de serviços para habilitar
				 cat_disable_services_owner :: list(binary()),		%% Lista de owners dos serviços para desativar
				 cat_enable_services_owner :: list(binary()),		%% Lista de owners de serviços para habilitar
				 cat_restricted_services_owner :: list(binary()),   %% Lista de owners de serviços restritos
				 cat_restricted_services_admin :: list(binary()),	%% Lista de admins que podem consumir os serviços
				 static_file_path :: list(string()),				%% Lista de diretórios para arquivos estáticos
				 static_file_path_map :: map(),					
				 static_file_path_probing :: boolean(),				%% Sonda a lista static_file_path para localizar contratos de serviços
				 ems_hostname :: binary(),							%% Nome da maquina onde o barramento está sendo executado
				 ems_host :: atom(),								%% Atom do name da maquina onde o barramento está sendo executado
				 ems_file_dest :: string(),							%% Nome do arquivo de configuração (útil para saber o local do arquivo)
				 ems_result_cache  :: non_neg_integer(),
				 ems_result_cache_enabled = true :: boolean(),
				 ems_datasources :: map(),
				 tcp_listen_address :: list(),
				 tcp_listen_address_t :: list(),
				 tcp_listen_main_ip :: binary(),
				 tcp_listen_main_ip_t :: tuple(),
				 tcp_listen_prefix_interface_names :: list(string()),
				 tcp_allowed_address :: list() | atom(),
				 authorization :: binary(),
				 oauth2_with_check_constraint :: boolean(),
				 oauth2_refresh_token :: non_neg_integer(),
				 oauth2_resource_owner_find_permission_with_cpf = true :: boolean(), %% Deve usar o cpf ou o id do user para buscar a lista de perfis e permissões?
				 oauth2_resource_owner_fields :: list(binary()),    %% Lista de campos que devem aparecer no resource_owner na autenticação oauth2
				 auth_allow_user_inative_credentials :: boolean(),	%% Permite login de usuários inativos.
				 rest_base_url :: binary(),
				 rest_base_auth_url :: binary(),
				 rest_auth_url :: binary(),
				 rest_login_url :: binary(),						%% Url da tela de login
				 rest_use_host_in_redirect :: boolean(),			%% Ao gerar a url de redirect, usa o host para a o dominio 
				 rest_url_mask :: boolean(),
				 rest_default_querystring :: map(),					%% querystring default
				 rest_environment :: binary(),
				 rest_user :: string(),
				 rest_passwd :: string(),
				 rest_base_url_defined = false :: boolean(),
				 config_file,
				 http_port_offset :: non_neg_integer(),
				 https_port_offset :: non_neg_integer(),
 				 http_enable :: boolean(),
 				 https_enable :: boolean(),
 				 force_https :: boolean(),
 				 http_max_content_length :: non_neg_integer(),
				 params :: map(),
				 client_path_search :: string(),
				 user_path_search :: string(),
				 user_dados_funcionais_path_search :: string(),
				 user_perfil_path_search :: string(),
				 user_permission_path_search :: string(),
				 user_email_path_search :: string(),
				 user_endereco_path_search :: string(),
				 user_telefone_path_search :: string(),
				 ssl_cacertfile :: binary(),
				 ssl_certfile :: binary(),
				 ssl_keyfile :: binary(),
				 sufixo_email_institucional :: binary(),
				 log_show_response = ?LOG_SHOW_RESPONSE :: boolean(),						%% Se true, imprime o response no log
				 log_show_response_header = ?LOG_SHOW_RESPONSE_HEADER :: boolean(),			%% Se true, imprime o response no log
				 log_show_payload = ?LOG_SHOW_PAYLOAD :: boolean(),				%% Se true, imprime o payload no log
				 log_show_response_max_length :: non_neg_integer(),			%% show response if content length < show_response_max_length
				 log_show_payload_max_length :: non_neg_integer(),			%% show payload if content length < show_response_max_length
				 log_show_odbc_pool_activity = true :: boolean(),	%% Se true, vai mostrar a atividade do pool de conexões
				 log_show_data_loader_activity = true :: boolean(),	%% Se true, vai mostrar a atividade dos data loaders
				 log_show_content_static_file = ?LOG_SHOW_CONTENT_STATIC_FILE :: boolean(),				%% Se true, imprime o conteúdo do arquivo no log
				 smtp_passwd :: string(),
				 smtp_from :: string(),
				 smtp_mail :: string(),
				 smtp_port :: non_neg_integer(),
				 ldap_url :: string(),
				 ldap_admin :: string(),
				 ldap_password_admin :: string(),
				 ldap_password_admin_crypto :: string(),
				 ldap_base_search :: string(),
 				 custom_variables :: list(binary()),						%% Lista de variáveis genéricas
 				 rate_limit_interno :: non_neg_integer(),
 				 rate_limit_externo :: non_neg_integer(),
 				 rate_limit_cidr_interno :: any(),
  				 priv_path :: string(),
 				 database_path :: string(),
 				 log_path :: string(),
 				 www_path :: string(),
 				 auth_default_scope :: list(atom()),
 				 auth_password_check_between_scope :: boolean(),
 				 oauth2_jwt_secret :: binary(),
 				 crypto_blowfish_module_path :: string(),
				 user_agent_denied_list :: list(binary()),
				 debug = false :: boolean()
		 }). 	
