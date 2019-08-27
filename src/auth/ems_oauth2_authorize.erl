-module(ems_oauth2_authorize).

-export([execute/1, 
		 code_request/1]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").


execute(Request = #request{type = Type, 
						   timestamp = Timestamp,
						   user_agent = UserAgent, 
						   user_agent_version = UserAgentVersion,
						   response_header = ResponseHeader,
						   host = Host,
						   service  = Service = #service{oauth2_allow_client_credentials = OAuth2AllowClientCredentials}}) -> 
	try
		PassportCodeBinBase64 = ems_util:get_querystring(<<"passport">>, <<>>, Request),
		case parse_passport_code(PassportCodeBinBase64) of
			{error, eno_passport_present} ->		
				case Type of
					<<"GET">> -> 
						GrantType = ems_util:get_querystring(<<"response_type">>, <<>>, Request),
						ems_logger:info("ems_oauth2_authorize autenticate by oauth2 GrantTytpe: ~p.", [binary_to_list(GrantType)]);
					<<"POST">> -> 
						GrantType = ems_util:get_querystring(<<"grant_type">>, <<>>, Request),
						ems_logger:info("ems_oauth2_authorize autenticate by oauth2 GrantTytpe: ~p.", [binary_to_list(GrantType)]);
					_ -> 
						GrantType = undefined
				end,
				Result = case GrantType of
						<<"password">> -> 
							case ems_util:get_client_request_by_id_and_secret(Request) of
								{ok, Client0} -> 
									ems_db:inc_counter(ems_oauth2_grant_type_password),
									password_grant(Request, Client0);
								_ -> password_grant(Request, undefined) % cliente é opcional no grant_type password
							end;
						<<"client_credentials">> ->
							case ems_util:get_client_request_by_id_and_secret(Request) of
								{ok, Client0} ->
									case OAuth2AllowClientCredentials of
										true ->
											ems_db:inc_counter(ems_oauth2_grant_type_client_credentials),
											client_credentials_grant(Request, Client0);
										false ->
											ems_db:inc_counter(ems_oauth2_client_credentials_denied),
											{error, access_denied, eoauth2_client_credentials_denied}	
									end;
								Error -> Error
							end;
						<<"token">> -> 
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									ems_db:inc_counter(ems_oauth2_grant_type_token),
									authorization_request(Request, Client0);
								Error -> Error
							end;
						<<"code">> ->	
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									ems_db:inc_counter(ems_oauth2_grant_type_code),
									authorization_request(Request, Client0);	
								Error -> Error
							end;
						<<"authorization_code">> ->	
							case ems_util:get_client_request_by_id_and_secret(Request) of
								{ok, Client0} -> 
									ems_db:inc_counter(ems_oauth2_grant_type_authorization_code),
									access_token_request(Request, Client0);
								{error, ReasonAuthorizationCode} = Error -> 
									ems_logger:info("ems_oauth2_authorize execute authorization_code failed in get_client_request_by_id_and_secret. Reason: ~p.", [ReasonAuthorizationCode]),
									Error
							end;
						<<"refresh_token">> ->	
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									ems_db:inc_counter(ems_oauth2_grant_type_refresh_token),
									refresh_token_request(Request, Client0);	
								Error -> Error
							end;
						 _ -> 
							ems_logger:error("ems_oauth2_authorize failed on parse invalid grant_type ~p.", [GrantType]),
							{error, access_denied, einvalid_grant_type}
				end; 
			{ok, PassportCodeInt, Client0, User0} ->
				ems_logger:info("ems_oauth2_authorize autenticate by passport PassportCodeInt: ~p Client: ~p User: ~p.", [PassportCodeInt, Client0, User0]),
				GrantType = <<"authorization_code">>,
				ems_db:inc_counter(ems_oauth2_passport),
				Result = password_grant_passport(Request, binary_to_list(PassportCodeBinBase64), PassportCodeInt, Client0, User0)	
		end,
		case Result of
			{ok, [ {<<"access_token">>,AccessToken},
				   {<<"expires_in">>, ExpireIn},
				   {<<"resource_owner">>, User},
				   {<<"scope">>, Scope},
				   {<<"refresh_token">>, RefreshToken},
				   {<<"refresh_token_expires_in">>, RefreshTokenExpireIn},
				   {<<"token_type">>, TokenType}
				 ], 
				 Client
			 } ->
					% When it is authorization_code, we will record metrics for singlesignon
					case User =/= undefined of
						true -> 
							UserAgentBin = ems_util:user_agent_atom_to_binary(UserAgent),
							SingleSignonUserAgentMetricName = binary_to_atom(iolist_to_binary([<<"ems_oauth2_singlesignon_user_agent_">>, UserAgentBin, <<"_">>, UserAgentVersion]), utf8),
							ems_db:inc_counter(SingleSignonUserAgentMetricName);
						false -> ok
					end,
					case Client =/= undefined of
						true ->
							ClientJson = ems_client:to_json(Client),
							ResourceOwner = ems_user:to_resource_owner(User, Client#client.id),
							ClientProp = [<<"\"client\":"/utf8>>, ClientJson, <<","/utf8>>];
						false ->
							ResourceOwner = ems_user:to_resource_owner(User),
							ClientProp = <<"\"client\": \"public\","/utf8>>
					end,
					% Persiste os tokens somente quando um user e um cliente foi informado
					case User =/= undefined andalso Client =/= undefined of
						true -> persist_token_sgbd(Service, User, Client, AccessToken, Scope, UserAgent, UserAgentVersion);
						false -> ok
					end,
					ResponseData2 = iolist_to_binary([<<"{"/utf8>>,
															ClientProp,
														   <<"\"access_token\":\""/utf8>>, AccessToken, <<"\","/utf8>>,
														   <<"\"expires_in\":"/utf8>>, integer_to_binary(ExpireIn), <<","/utf8>>,
														   <<"\"resource_owner\":"/utf8>>, ResourceOwner, <<","/utf8>>,
														   <<"\"scope\":\""/utf8>>, Scope, <<"\","/utf8>>,
														   <<"\"refresh_token\":\""/utf8>>, case RefreshToken of
																									undefined -> <<>>;
																									_ -> RefreshToken
																							end, <<"\","/utf8>>, 
															<<"\"refresh_token_in\":"/utf8>>, case RefreshTokenExpireIn of 
																									undefined -> <<"0">>; 
																									_ -> integer_to_binary(RefreshTokenExpireIn) 
																							 end, <<","/utf8>>,
														   <<"\"token_type\":\""/utf8>>, TokenType, <<"\""/utf8>>,
													   <<"}"/utf8>>]),
					Request2 = Request#request{code = 200, 
											    reason = ok,
											    operation = oauth2_authenticate,
											    response_data = ResponseData2,
											    oauth2_grant_type = GrantType,
											    oauth2_access_token = AccessToken,
											    oauth2_refresh_token = RefreshToken,
											    client = Client,
											    user = User,
											    content_type_out = ?CONTENT_TYPE_JSON},
					{ok, Request2};		
			{redirect, Client = #client{id = ClientId, name = Name, redirect_uri = RedirectUri}} ->
					ClientIdBin = integer_to_binary(ClientId),
					ems_db:inc_counter(binary_to_atom(iolist_to_binary([<<"ems_oauth2_singlesignon_client_">>, ClientIdBin]), utf8)),
					Config = ems_config:getConfig(),
					case Config#config.rest_use_host_in_redirect of
						true -> LocationPath = iolist_to_binary([<<"http://"/utf8>>, Host, <<"/login/index.html?response_type=code&client_id=">>, ClientIdBin, <<"&redirect_uri=">>, RedirectUri]);
						false -> LocationPath = iolist_to_binary([Config#config.rest_login_url, <<"?response_type=code&client_id=">>, ClientIdBin, <<"&redirect_uri=">>, RedirectUri])
					end,
					ems_logger:info("ems_oauth2_authorize redirect client ~p ~s to ~p.", [ClientId, binary_to_list(Name), binary_to_list(LocationPath)]),
					case Config#config.instance_type == production of
						true ->
							ExpireDate = ems_util:date_add_minute(Timestamp, 1 + 180), % add +120min (2h) para ser horário GMT
							Expires = cowboy_clock:rfc1123(ExpireDate),
							Request2 = Request#request{code = 302, 
													   reason = ok,
													   operation = oauth2_client_redirect,
													   oauth2_grant_type = GrantType,
													   client = Client,
													   response_header = ResponseHeader#{<<"location">> => LocationPath,
																						 <<"cache-control">> => ?CACHE_CONTROL_1_MIN,
																						 <<"expires">> => Expires}
													};
						false ->
							Request2 = Request#request{code = 302, 
													   reason = ok,
													   operation = oauth2_client_redirect,
													   oauth2_grant_type = GrantType,
													   client = Client,
													   response_header = ResponseHeader#{<<"location">> => LocationPath,
																						 <<"cache-control">> => ?CACHE_CONTROL_NO_CACHE}
														}
					end,
					{ok, Request2};
			{error, Reason, ReasonDetail} ->
					% Para finalidades de debug, tenta buscar o user pelo login para armazenar no log
					case ems_util:get_user_request_by_login(Request) of
						{ok, UserFound} -> User = UserFound;
						_ -> User = undefined
					end,
					Request2 = Request#request{code = 401, 
											   reason = Reason,
											   reason_detail = ReasonDetail,
											   operation = oauth2_authenticate,
											   oauth2_grant_type = GrantType,
											   response_data = ?ACCESS_DENIED_JSON,
											   user = User},
					{error, Request2}
		end
	catch
		_:ReasonException ->
			Request3 = Request#request{code = 401, 
									   reason = access_denied,
									   reason_detail = eparse_oauth2_authorize_execute,
									   reason_exception = ReasonException,
									   operation = oauth2_authenticate,
									   user = undefined,
									   client = undefined,
									   response_data = ?ACCESS_DENIED_JSON},
			{error, Request3}
	end.

%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
code_request(Request = #request{response_header = ResponseHeader}) ->
	io:format("aqui1  ~p\n", [Request]),
    try
		case ems_util:get_client_request_by_id(Request) of
			{ok, Client} ->
				case ems_util:get_user_request_by_login_and_password(Request, Client) of
					{ok, User} ->
						RedirectUri = ems_util:to_lower_and_remove_backslash(ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request)),
						Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),
						case get_code_by_user_and_client(User, Client, Scope) of
							{ok, Code} ->
								LocationPath = iolist_to_binary([RedirectUri, <<"?code=">>, Code]),
								Request2 = Request#request{code = 200, 
														   reason = ok,
														   operation = oauth2_authenticate,
														   user = User,
														   client = Client,
														   response_data = <<"{}">>,
														   response_header = ResponseHeader#{<<"location">> => LocationPath}},
								%ems_user:add_history(User, Client, Request2#request.service, Request2),
								{ok, Request2};
							{error, Reason} ->
								Request2 = Request#request{code = 401, 
														   reason = Reason,
														   reason_detail = get_code_by_user_and_client_failed,
														   operation = oauth2_authenticate,
														   user = User,
														   client = Client,
														   response_data = ?ACCESS_DENIED_JSON},
								%ems_user:add_history(User, Client, Request2#request.service, Request2),
								{error, Request2}
						end;
					{error, Reason, ReasonDetail} ->
						% Para finalidades de debug, tenta buscar o user pelo login para armazenar no log
						case ems_util:get_user_request_by_login(Request) of
							{ok, UserFound} -> User = UserFound;
							_ -> User = undefined
						end,
						Request2 = Request#request{code = 401, 
												   reason = Reason,
												   reason_detail = ReasonDetail,
												   operation = oauth2_authenticate,
												   user = User,
												   client = Client,
												   response_data = ?ACCESS_DENIED_JSON},
						{error, Request2}
				end;
			{error, Reason, ReasonDetail} ->
				Request2 = Request#request{code = 401, 
											reason = Reason,
											reason_detail = ReasonDetail,
											operation = oauth2_authenticate,
											user = undefined,
											client = undefined,
											response_data = ?ACCESS_DENIED_JSON},
				{error, Request2}
		end
	catch
		_:ReasonException ->
			Request3 = Request#request{code = 401, 
										reason = access_denied,
										reason_detail = eparse_code_request_exception,
										reason_exception = ReasonException,
										operation = oauth2_authenticate,
										user = undefined,
										client = undefined,
										response_data = ?ACCESS_DENIED_JSON},
			{error, Request3}
	end.

	
%%%===================================================================
%%% Funções internas
%%%===================================================================


%% Cliente Credencial Grant- seção 4.4.1 do RFC 6749. 
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=client_credentials&client_id=s6BhdRkqt3&secret=qwer
-spec client_credentials_grant(#request{}, #client{}) -> {ok, list(), #client{}} | {error, access_denied, atom()}.
client_credentials_grant(Request, Client) ->
	try
		Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),	
		Authz = oauth2:authorize_client_credentials(Client, Scope, []),
		issue_token(Authz, Client)
	catch
		_:_ -> {error, access_denied, eparse_client_credentials_grant_exception}
	end.


%% Resource Owner Password Credentials Grant - seção 4.3.1 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=password&username=johndoe&password=A3ddj3w
-spec password_grant(#request{}, #client{}) -> {ok, list(), #client{}} | {error, access_denied, atom()}.
password_grant(Request, Client) -> 
	try
		case ems_util:get_user_request_by_login_and_password(Request, Client) of
			{ok, User} ->
				Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),	
				case Client == undefined of
					true -> Authz = oauth2:authorize_password(User, Scope, []);
					false -> Authz = oauth2:authorize_password(User, Client, Scope, [])
				end,
				issue_token(Authz, Client);
			Error -> Error
		end
	catch
		_:_ -> {error, access_denied, eparse_password_grant_exception}
	end.


-spec password_grant_passport(#request{}, string(), non_neg_integer(), #client{}, #user{}) -> {ok, list(), #client{}} | {error, access_denied, atom()}.
password_grant_passport(Request, PassportCodeBase64, PassportCodeInt, Client, User) -> 
	try
		Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),	
		case Client == undefined of
			true -> 
				Authz = oauth2:authorize_password(User, Scope, []),
				ems_logger:info("ems_oauth2_authorize autenticate passport ~s (~p) user ~p.", [PassportCodeBase64, PassportCodeInt,
																						  integer_to_list(User#user.id) ++ " - " ++ User#user.name]);
			false -> 
				Authz = oauth2:authorize_password(User, Client, Scope, []),
				ems_logger:info("ems_oauth2_authorize autenticate passport ~s (~p) client ~p  user ~p.", [PassportCodeBase64, PassportCodeInt,
																									 integer_to_list(Client#client.id) ++ " - " ++ Client#client.name, 
																									 integer_to_list(User#user.id) ++ " - " ++ User#user.name])
		end,
		issue_token(Authz, Client)
	catch
		_:_ -> {error, access_denied, eparse_password_grant_pass_exception}
	end.
	
%% Verifica a URI do Cliente e redireciona para a página de autorização - Implicit Grant e Authorization Code Grant
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html
-spec authorization_request(#request{}, #client{}) -> {ok, list()} | {error, access_denied, atom()}.
authorization_request(Request, Client) ->
    try
		RedirectUri = ems_util:to_lower_and_remove_backslash(ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request)),
		case ems_oauth2_backend:verify_redirection_uri(Client, RedirectUri, []) of
			{ok, _} -> {redirect, Client};
			_ -> {error, access_denied, einvalid_redirection_uri}
		end
	catch
		_:_ -> {error, access_denied, eparse_authorization_request_exception}
	end.


%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
-spec refresh_token_request(#request{}, #client{}) -> {ok, list()} | {error, access_denied, atom()}.
refresh_token_request(Request, Client) ->
	try
		case ems_util:get_querystring(<<"refresh_token">>, <<>>, Request) of
			<<>> -> {error, access_denied, erefresh_token_empty};
			RefleshToken ->
				Scope = ems_util:get_querystring(<<"scope">>, <<>>, Request),
				Authz = ems_oauth2_backend:authorize_refresh_token(Client, RefleshToken, Scope),
				issue_token(Authz, Client)
		end
	catch
		_:_ -> {error, access_denied, eparse_refresh_token_request_exception}
	end.


%% Requisita o token de acesso com o código de autorização - seções  4.1.3. e  4.1.4 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=authorization_code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w&secret=qwer&code=dxUlCWj2JYxnGp59nthGfXFFtn3hJTqx
-spec access_token_request(#request{}, #client{}) -> {ok, list()} | {error, access_denied, atom()}.
access_token_request(Request, Client) ->
	try
		case ems_util:get_querystring(<<"code">>, <<>>, Request) of
			<<>> -> {error, access_denied, ecode_empty};
			Code -> 
				RedirectUri = ems_util:to_lower_and_remove_backslash(ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request)),
				Authz = oauth2:authorize_code_grant(Client, Code, RedirectUri, []),
				issue_token_and_refresh(Authz, Client)
		end
	catch
		_:_ -> {error, access_denied, eparse_access_token_request}
	end.
	

issue_token({ok, {_, Auth}}, Client) ->
	case oauth2:issue_token(Auth, []) of
		{ok, {_, {response, AccessToken, 
							undefined,
							ExpiresIn,
							User,
							Scope, 
							RefreshToken, 
							RefreshTokenExpiresIn,
							TokenType
				 }
			}} ->
				{ok, [{<<"access_token">>, AccessToken},
						{<<"expires_in">>, ExpiresIn},
						{<<"resource_owner">>, User},
						{<<"scope">>, Scope},
						{<<"refresh_token">>, RefreshToken},
						{<<"refresh_token_expires_in">>, RefreshTokenExpiresIn},
						{<<"token_type">>, TokenType}], Client};
		_ -> {error, access_denied, einvalid_issue_token}
	end;
issue_token(_, _) -> {error, access_denied, einvalid_authorization}.
    

issue_token_and_refresh({ok, {_, Auth}}, Client) ->
	case oauth2:issue_token_and_refresh(Auth, []) of
		{ok, {_, {response, AccessToken, 
							undefined,
							ExpiresIn,
							User,
							Scope, 
							RefreshToken, 
							RefreshTokenExpiresIn,
							TokenType
				 }
			}} ->
				{ok, [{<<"access_token">>, AccessToken},
						{<<"expires_in">>, ExpiresIn},
						{<<"resource_owner">>, User},
						{<<"scope">>, Scope},
						{<<"refresh_token">>, RefreshToken},
						{<<"refresh_token_expires_in">>, RefreshTokenExpiresIn},
						{<<"token_type">>, TokenType}], Client};
		_ -> {error, access_denied, einvalid_issue_token_and_refresh}
	end;
issue_token_and_refresh(_, _) -> 
	{error, access_denied, einvalid_authorization}.


issue_code({ok, {_, Auth}}) ->
	case oauth2:issue_code(Auth, []) of
		{ok, {_, Response}} ->	
			{ok, oauth2_response:to_proplist(Response)};
		_ -> {error, access_denied, einvalid_issue_code}
	end;
issue_code(_) -> {error, access_denied, eparse_issue_code_exception}.

-spec get_code_by_user_and_client(#user{}, #client{}, binary()) -> {ok, binary()} | {error, enoent}.
get_code_by_user_and_client(User, Client = #client{redirect_uri = RedirectUri}, Scope) ->
	Authz = oauth2:authorize_code_request(User, Client, RedirectUri, Scope, []),
	case issue_code(Authz) of
		{ok, ResponseCode} -> {ok, element(2, lists:nth(1, ResponseCode))};
		_ -> {ok, enoent}
	end.


persist_token_sgbd(#service{properties = Props}, User = #user{ id = IdUsuario, codigo = IdPessoa, ctrl_source_type = CtrlSourceType }, Client = #client{name = ClientNameBin}, AccessToken, Scope, UserAgentAtom, UserAgentVersionBin) ->
	SqlPersist = ems_util:str_trim(binary_to_list(maps:get(<<"sql_persist">>, Props, <<>>))),
	SqlFixClientName = maps:get(<<"sql_fix_client_name">>, Props, <<>>),
	case SqlFixClientName of
		<<>> -> ClientName = binary_to_list(ClientNameBin);
		_ -> ClientName = binary_to_list(SqlFixClientName)
	end,
	case SqlPersist =/= "" andalso CtrlSourceType =/= user_fs of
		true ->
			{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
			case ems_odbc_pool:get_connection(Ds) of
				{ok, Ds2} ->
					AccessToken2 = binary_to_list(AccessToken),
					{ok, CodeBin} = get_code_by_user_and_client(User, Client, Scope),
					Code = binary_to_list(CodeBin),
					ParamsSql = [{{sql_varchar, 32}, [ClientName]},	% Client name
								  {sql_integer, [IdPessoa]},
								  {sql_integer, [IdUsuario]},
								  {{sql_varchar, 32}, [AccessToken2]},					% Token
								  {{sql_varchar, 32}, [Code]},							% Device ID (Code) 
								  {{sql_varchar, 32}, [atom_to_list(UserAgentAtom) ++ " " ++ binary_to_list(UserAgentVersionBin)]}],	% Device Info
					ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
					ems_odbc_pool:release_connection(Ds2);
				{error, Reason} ->
					ems_logger:error("ems_oauth2_authorize persist_token_sgbd failed to get database connection. Reason: ~p.", [Reason])
			end;
		false -> ok
	end,
	ok.


parse_passport_code(<<>>) -> {error, eno_passport_present};
parse_passport_code(undefined) -> {error, eno_passport_present};
parse_passport_code(<<"undefined">>) -> {error, eno_passport_present};
parse_passport_code(PassportCodeBinBase64) ->
	try
		PassportCodeBinBase64Str = ems_util:remove_quoted_str(binary_to_list(PassportCodeBinBase64)),
		PassportCodeStr = base64:decode_to_string(PassportCodeBinBase64Str),
		PassportCodeStr2 = ems_util:str_trim(PassportCodeStr),
		PassportCodeInt = ems_util:list_to_integer_def(PassportCodeStr2, 0),
		case PassportCodeInt > 0 andalso PassportCodeInt =< 9999999999 of
			true -> 
				case select_passport_code_sgbd(PassportCodeBinBase64Str, PassportCodeInt) of
					{ok, ClientId, UserId, _DtCreated, Escopo} ->
						case ems_client:find_by_id(ClientId) of
							{ok, Client} ->
								case ems_user:find_by_id(UserId, Escopo) of
									{ok, User} -> 
										{ok, PassportCodeInt, Client, User};
									_ -> 
										ems_logger:error("ems_oauth2_authorize parse_passport_code failed to find user of passport ~s (~s).", [PassportCodeBinBase64Str, PassportCodeStr2]),
										{error, eno_passport_present}
								end;
							_ -> 
								ms_logger:error("ems_oauth2_authorize parse_passport_code failed to find client of passport ~s (~s).", [PassportCodeBinBase64Str, PassportCodeStr2]),
								{error, eno_passport_present}
						end;
					_ -> 
						{error, eno_passport_present}
				end;
			false ->
				ems_logger:error("ems_oauth2_authorize parse_passport_code failed to parse invalid numeric passport ~s (~s).", [PassportCodeBinBase64Str, PassportCodeStr2]),
				{error, eno_passport_present}
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_authorize parse_passport_code failed to parse invalid passport ~p. Reason: ~p.", [PassportCodeBinBase64, ReasonException]),
			{error, eno_passport_present}
	end.

	
select_passport_code_sgbd(PassportCodeBinBase64, PassportCodeInt) ->
	PassportEnabled = ems_db:get_param(passport_code_enabled),
	case PassportEnabled of
		true ->
			DatasourcePassportCode = ems_db:get_param(datasource_passport_code),
			SqlSelectPassportCode = ems_db:get_param(sql_select_passport_code),
			case SqlSelectPassportCode =/= "" andalso DatasourcePassportCode =/= <<>> of
				true ->
					case ems_db:find_first(service_datasource, [], [{ds_name, "==", DatasourcePassportCode}]) of
						{ok, Ds} ->
							case ems_odbc_pool:get_connection(Ds) of
								{ok, Ds2} ->
									ParamsSql = [{sql_integer, [PassportCodeInt]}],
									case ems_odbc_pool:param_query(Ds2, SqlSelectPassportCode, ParamsSql) of
										{selected, _Fields, [{ClientId, UserId, DtCreated, Escopo}]} ->
											disable_passport_code_sgbd(PassportCodeBinBase64, PassportCodeInt),
											Result = {ok, ClientId, UserId, DtCreated, list_to_atom(Escopo)};
										{_, _, []} -> 
											ems_logger:error("ems_oauth2_authorize select_passport_code_sgbd does not find passport ~s (~p). Reason: passport inexistent or disabled.", [PassportCodeBinBase64, PassportCodeInt]),
											Result = {error, einexistent_passport_code};
										{error, Reason2} ->
											ems_logger:error("ems_oauth2_authorize select_passport_code_sgbd failed to query select for passport ~s (~p). Reason: ~p.", [PassportCodeBinBase64, PassportCodeInt, Reason2]),
											Result = {error, eparam_query_error_passport_code} 
									end,
									ems_odbc_pool:release_connection(Ds2),
									Result;
								{error, Reason} ->
									ems_logger:error("ems_oauth2_authorize select_passport_code_sgbd failed to get database connection for passport ~s (~p). Reason: ~p.", [PassportCodeBinBase64, PassportCodeInt, Reason]),
									{error, einvalid_database_connection_passport} 
							end;
						_ ->
							ems_logger:error("ems_oauth2_authorize select_passport_code_sgbd failed to get database datasource for passport ~s (~p).", [PassportCodeBinBase64, PassportCodeInt]),
							{error, einvalid_database_datasource_passport} 
					end;
				false -> 
					ems_logger:error("ems_oauth2_authorize select_passport_code_sgbd failed to get config on catalog ems_oauth2_backend for passport ~s (~p).", [PassportCodeBinBase64, PassportCodeInt]),
					{error, einexistent_config_passport}
			end;
		false ->
			ems_logger:error("ems_oauth2_authorize passport autenticate is disabled on catalog ems_oauth2_backend."),
			{error, epassport_autenticate_disabled}
	end.


disable_passport_code_sgbd(PassportCodeBinBase64, PassportCodeInt) ->
	DatasourcePassportCode = ems_db:get_param(datasource_passport_code),
	SqlDisablePassportCode = ems_db:get_param(sql_disable_passport_code),
	case SqlDisablePassportCode =/= "" andalso DatasourcePassportCode =/= <<>> of
		true ->
			case ems_db:find_first(service_datasource, [], [{ds_name, "==", DatasourcePassportCode}]) of
				{ok, Ds} ->
					case ems_odbc_pool:get_connection(Ds) of
						{ok, Ds2} ->
							ParamsSql = [{sql_integer, [PassportCodeInt]}],
							ems_odbc_pool:param_query(Ds2, SqlDisablePassportCode, ParamsSql),
							ems_odbc_pool:release_connection(Ds2),
							ok;
						{error, Reason} ->
							ems_logger:error("ems_oauth2_authorize disable_passport_code_sgbd failed to get database connection for passport ~s (~p). Reason: ~p.", [PassportCodeBinBase64, PassportCodeInt, Reason]),
							{error, einvalid_database_connection_passport} 
					end;
				_ ->
					ems_logger:error("ems_oauth2_authorize disable_passport_code_sgbd failed to get database datasource for passport ~s (~p).", [PassportCodeBinBase64, PassportCodeInt]),
					{error, einvalid_database_datasource_passport} 
			end;
		false -> 
			ok   %% desabilitar o passport eh opcional
	end.
