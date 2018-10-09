%%********************************************************************
%% @title Arquivo de configuração ErlangMS
%% @version 1.0.0
%% @doc Arquivo com configurações gerais de funcionamento de ErlangMS.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-define(DEBUG(Msg), ems_logger:debug(Msg)).
-define(DEBUG(Msg, Params), ems_logger:debug(Msg, Params)).

-ifdef(native_json).
	-define(JSON_LIB, jiffy).
-else.
	-define(JSON_LIB, jsx).
-endif.

-ifdef(win32_plataform).
	-define(UTF8_STRING(Text), ems_util:utf8_string_win(Text)).
-else.
	-define(UTF8_STRING(Text), ems_util:utf8_string_linux(Text)).
-endif.

% Nome do servidor
-define(SERVER_NAME, ems_util:server_name()).


% Caminho do diretório privado
-define(PRIV_PATH, ems_util:get_priv_dir()).

% Caminho do diretório de trabalho
-define(WORKING_PATH, ems_util:get_working_dir()).

% Caminho do diretório privado
-define(TEMP_PATH, filename:join(?PRIV_PATH, "tmp")).

% Caminho do catálogo de serviços
-define(CONF_PATH, filename:join(?PRIV_PATH, "conf")).

% Caminho da pasta log
-define(LOG_PATH, filename:join(?PRIV_PATH, "log")).

% Caminho do favicon
-define(FAVICON_PATH, filename:join(?PRIV_PATH, "favicon.ico")).

% Caminho do catálogo de serviços
-define(CATALOGO_PATH, filename:join(?PRIV_PATH, "catalog")).

% Caminho do catálogo de serviços
-define(CATALOGO_ESB_PATH, filename:join(?CATALOGO_PATH, "catalog.json")).

% Caminho da pasta de databases
-define(DATABASE_PATH, filename:join(?PRIV_PATH, "db")).

% Caminho da pasta de databases
-define(JAR_PATH, filename:join(?PRIV_PATH, "jar")).

% Caminho do arquivo de configuração padrão (Pode ser incluído também na pasta ~/.erlangms do usuário)
-define(CONF_FILE_PATH, filename:join(?CONF_PATH, "emsbus.conf")).

% Caminho inicial para os arquivos estáticos
-define(STATIC_FILE_PATH, filename:join(?PRIV_PATH, "www")).

% Sonda a lista static_file_path para localizar contratos de serviços
-define(STATIC_FILE_PATH_PROBING, false).

% Caminho do arquivo de clientes
-define(CLIENT_PATH, filename:join(?CONF_PATH, "clients.json")).

% Caminho do arquivo de usuários
-define(USER_PATH, filename:join(?CONF_PATH, "users.json")).

% Caminho do arquivo de dados funcionais dos usuários
-define(USER_DADOS_FUNCIONAIS_PATH, filename:join(?CONF_PATH, "user_dados_funcionais.json")).

% Caminho do arquivo de dados funcionais dos usuários
-define(USER_EMAIL_PATH, filename:join(?CONF_PATH, "user_email.json")).

% Caminho do arquivo de perfis dos usuários
-define(USER_PERFIL_PATH, filename:join(?CONF_PATH, "user_perfil.json")).

% Caminho do arquivo de permissões dos usuários
-define(USER_PERMISSION_PATH, filename:join(?CONF_PATH, "user_permission.json")).

% Caminho do arquivo de endereços dos usuários
-define(USER_ENDERECO_PATH, filename:join(?CONF_PATH, "user_endereco.json")).

% Caminho do arquivo de telefones dos usuários
-define(USER_TELEFONE_PATH, filename:join(?CONF_PATH, "user_telefone.json")).

% Caminho inicial para os arquivos estáticos
-define(WEBAPPS_PATH, filename:join(?PRIV_PATH, "www")).

% Caminho inicial para os arquivos de carga de dados em formato CSV
-define(CSV_FILE_PATH, filename:join(?PRIV_PATH, "csv")).

% Caminho dos certificados ssl
-define(SSL_PATH, filename:join(?PRIV_PATH, "ssl")).

% Mostra no log payload e response
-define(LOG_SHOW_RESPONSE, true).
-define(LOG_SHOW_PAYLOAD, true).

% Armazena o buffer do log a cada LOG_FILE_CHECKPOINT ms (Aumente este valor se existir muita contenção de escrita em disco)
-define(LOG_FILE_CHECKPOINT, 400).  

% Tamanho em KB máximo permitido para os arquivos de logs
-define(LOG_FILE_MAX_SIZE, 51200000).  

% Arquiva o log a cada LOG_ARCHIVE_CHECKPOINT ms
-define(LOG_ARCHIVE_CHECKPOINT, 1000 * 60 * 60 * 24).  % Por default são 24 horas

% Define o tamanho máximo default que pode ser impresso no log do payload e response para depuração
-define(LOG_SHOW_PAYLOAD_MAX_LENGTH, 64000).
-define(LOG_SHOW_RESPONSE_MAX_LENGTH, 64000).

% Mostra cabeçalhos de depuração
-define(SHOW_DEBUG_RESPONSE_HEADERS, true).

% Quantos workers HTTP instanciar se não especificado no arquivo de configuração
-define(MIN_HTTP_WORKER, 1).

% Quantos workers HTTP instanciar se não especificado no arquivo de configuração
-define(MAX_HTTP_WORKER, 1000).

% Quantos workers HTTP são permitidos especificar no arquivo de configuração (1 até MAX_HTTP_WORKER_RANGE)
-define(MAX_HTTP_WORKER_RANGE, 1000). 

% Quanto tempo o dispatcher aguardar um serviço
-define(SERVICE_TIMEOUT, 60000). 		 % 1 minuto é o tempo padrão que o dispatcher aguarda um serviço executar
-define(SERVICE_MIN_TIMEOUT, 1000). 	 % 1 segundo é o tempo mínimo que o dispatcher aguarda um serviço executar
-define(SERVICE_MAX_TIMEOUT, 604800000). % 7 dias é o tempo máximo que o dispatcher aguarda um serviço executar
-define(SERVICE_MIN_EXPIRE_MINUTE, 0).
-define(SERVICE_MAX_EXPIRE_MINUTE, 525601). % 1 ano

% Range de tempo para iniciar processos kernel
-define(START_TIMEOUT, 1000).
-define(START_TIMEOUT_MIN, 0).
-define(START_TIMEOUT_MAX, 86400000).

% Caminho do utilitário que importa dados csv para um banco sqlite
-define(CSV2SQLITE_PATH, filename:join([?PRIV_PATH, "scripts", "csv2sqlite.py"])). 

% Quanto tempo uma parsed query mnesia fica em cache para reutilização (módulo ems_db)
-define(DB_PARSED_QUERY_CACHE_TIMEOUT, 60000). 

% Limits of API query
-define(MAX_LIMIT_API_QUERY, 99999999).
-define(MAX_OFFSET_API_QUERY, 99999).
-define(MAX_TIME_ODBC_QUERY, 960000).
-define(MAX_ID_RECORD_QUERY, 9999999999).  

% Timeout in ms to expire cache of get request (ems_dispatcher_cache)
-define(TIMEOUT_DISPATCHER_CACHE, 30000).

% Number of datasource entries by odbc connection pool
-define(MAX_CONNECTION_BY_POOL, 300).


% Timeout to check odbc connection
-define(CHECK_VALID_CONNECTION_TIMEOUT, 30000). % 60 segundos
-define(MAX_CLOSE_IDLE_CONNECTION_TIMEOUT, 3600000). % 1h
-define(CLOSE_IDLE_CONNECTION_TIMEOUT, 300000). % 5 minutos


% Define the default checkpoint to ems_data_loader and ems_json_loader
-define(DATA_LOADER_UPDATE_CHECKPOINT, 90000).


%Define the checkpoint to update permission for ems_user_permission_l
% HTTP access control (CORS) headers
-define(ACCESS_CONTROL_ALLOW_HEADERS, <<"Accept, Accept-Language, Content-Language, Content-Type, X-ACCESS_TOKEN, X-CSRF-Token, Access-Control-Allow-Origin, Authorization, Origin, x-requested-with, Content-Range, Content-Disposition, Content-Description">>).
-define(ACCESS_CONTROL_MAX_AGE, <<"31536000">>).
-define(ACCESS_CONTROL_ALLOW_ORIGIN, <<"*">>).
-define(ACCESS_CONTROL_ALLOW_METHODS, <<"GET, POST, PUT, DELETE, OPTIONS, HEAD">>).
-define(ACCESS_CONTROL_EXPOSE_HEADERS, <<"Cache-Control, Content-Language, Content-Type, Expires, Last-Modified, Pragma, Content-Length">>).


% Oauth2
-define(OAUTH2_DEFAULT_AUTHORIZATION, oauth2).
-define(AUTHORIZATION_TYPE_DEFAULT, <<"oauth2">>).

% Mensagens de saída json comuns
-define(CONTENT_TYPE_JSON, <<"application/json; charset=utf-8"/utf8>>).
-define(CACHE_CONTROL_NO_CACHE, <<"max-age=31536000, private, no-cache, no-store, must-revalidate"/utf8>>).
-define(CACHE_CONTROL_1_DAYS, <<"max-age=86400, public"/utf8>>).
-define(CACHE_CONTROL_30_DAYS, <<"max-age=2592000, private"/utf8>>).
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
-define(OAUTH2_DEFAULT_TOKEN_EXPIRY, 3600).  % 1 hour
-define(OAUTH2_MAX_TOKEN_EXPIRY, 2592000).   % 30 days

-define(HTTP_HEADERS_DEFAULT, #{<<"server">> => ?SERVER_NAME,
							    <<"cache-control">> => ?CACHE_CONTROL_NO_CACHE,
							    <<"access-control-allow-origin">> => ?ACCESS_CONTROL_ALLOW_ORIGIN,
							    <<"access-control-max-age">> => ?ACCESS_CONTROL_MAX_AGE,
							    <<"access-control-allow-headers">> => ?ACCESS_CONTROL_ALLOW_HEADERS,
							    <<"access-control-allow-methods">> => ?ACCESS_CONTROL_ALLOW_METHODS,
							    <<"access-control-expose-headers">> => ?ACCESS_CONTROL_EXPOSE_HEADERS
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
-define(HTTP_MAX_CONNECTIONS, 100000).
-define(HTTP_MAX_CONTENT_LENGTH, 524288).  % Limite default do conteúdo do payload é de 512KB
-define(HTTP_MAX_CONTENT_LENGTH_BY_SERVICE, 1048576000).  % Permite enviar até 1G se especificado no contrato de serviço


-define(TCP_PORT_MIN, 1024).
-define(TCP_PORT_MAX, 99999).


-ifdef(win32_plataform).
	-define(TCP_LISTEN_PREFIX_INTERFACE_NAMES, []).
-else.
	-define(TCP_LISTEN_PREFIX_INTERFACE_NAMES, [<<"lo">>, <<"enp">>, <<"eth">>, <<"wl">>, <<"eno">>]).
-endif.


-define(SUFIXO_EMAIL_INSTITUCIONAL, "@unb.br").

-define(RESULT_CACHE_MAX_SIZE_ENTRY, 524288). % 512KB
-define(RESULT_CACHE_SHARED, true). 



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
				 ems_debug :: boolean(),							%% Habilita o modo debug
				 ems_result_cache  :: non_neg_integer(),
				 ems_result_cache_shared :: non_neg_integer(),
				 ems_datasources :: map(),
				 show_debug_response_headers :: boolean(),			%% Add debug headers in HTTP response headers
				 tcp_listen_address :: list(),
				 tcp_listen_address_t :: list(),
				 tcp_listen_main_ip :: binary(),
				 tcp_listen_main_ip_t :: tuple(),
				 tcp_listen_prefix_interface_names :: list(string()),
				 tcp_allowed_address :: list() | atom(),
				 authorization :: binary(),
				 oauth2_with_check_constraint :: boolean(),
				 oauth2_refresh_token :: non_neg_integer(),
				 auth_allow_user_inative_credentials :: boolean(),	% Permite login de usuários inativos.
				 rest_base_url :: binary(),
				 rest_auth_url :: binary(),
				 rest_login_url :: binary(),						% Url da tela de login
				 rest_url_mask :: boolean(),
				 rest_default_querystring :: map(),					%% querystring default
				 rest_environment :: binary(),
				 rest_user :: string(),
				 rest_passwd :: string(),
				 config_file,
				 http_port_offset :: non_neg_integer(),
				 https_port_offset :: non_neg_integer(),
				 http_enable :: boolean(),
				 https_enable :: boolean(),
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
				 java_jar_path :: string(),
				 java_home :: string(),
 				 java_thread_pool :: non_neg_integer(),
				 ssl_cacertfile :: binary(),
				 ssl_certfile :: binary(),
				 ssl_keyfile :: binary(),
				 sufixo_email_institucional :: binary(),
				 http_headers :: map(),
				 http_headers_options :: map(),
				 log_show_response = false :: boolean(),			%% Se true, imprime o response no log
				 log_show_payload = false :: boolean(),				%% Se true, imprime o payload no log
				 log_show_response_max_length :: boolean(),			%% show response if content length < show_response_max_length
				 log_show_payload_max_length :: boolean(),			%% show payload if content length < show_response_max_length
				 log_file_checkpoint :: non_neg_integer(),
				 log_file_max_size :: non_neg_integer(),
				 smtp_passwd :: string(),
				 smtp_from :: string(),
				 smtp_mail :: string(),
				 smtp_port :: non_neg_integer(),
				 ldap_url :: string(),
				 ldap_admin :: string(),
				 ldap_password_admin :: string(),
				 ldap_password_admin_crypto :: string(),
				 ldap_base_search :: string(),
 				 custom_variables :: list(binary())						%% Lista de variáveis genéricas

		 }). 	

