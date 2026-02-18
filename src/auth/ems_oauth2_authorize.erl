-module(ems_oauth2_authorize).

-export([execute/1, 
		 code_request/1,
		 user_info/1]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").



execute(Request = #request{type = Type, 
						   user_agent = UserAgent,
						   response_header = ResponseHeader,
						   host = Host,
						   querystring = QuerystringBin,
						   service  = Service = #service{oauth2_allow_client_credentials = OAuth2AllowClientCredentials}}) -> 
	ems_data_loader_ctl:register_activity(auth),
	try
		PassportCodeBinBase64 = ems_util:get_querystring(<<"passport">>, <<>>, Request),
		case parse_passport_code(PassportCodeBinBase64) of
			{error, eno_passport_present} ->		
				case Type of
					<<"GET">> -> 
						GrantTypeRaw = ems_util:get_querystring(<<"response_type">>, <<>>, Request),
						GrantType = normalize_grant_type(GrantTypeRaw),
						ems_logger:info("ems_oauth2_authorize autenticate by oauth2 GrantType: ~p.", [binary_to_list(GrantType)]);
					<<"POST">> -> 
						GrantTypeRaw = ems_util:get_querystring(<<"grant_type">>, <<>>, Request),
						% Implicit default: if missing or empty, assume "0" (authorization_code)
						GrantTypeRaw2 = case GrantTypeRaw of
							<<>> -> <<"0">>;
							undefined -> <<"0">>;
							_ -> GrantTypeRaw
						end,
						GrantType = normalize_grant_type(GrantTypeRaw2),
						ems_logger:info("ems_oauth2_authorize autenticate by oauth2 GrantType: ~p.", [binary_to_list(GrantType)]);
					_ -> 
						GrantType = undefined
				end,
				Result = case GrantType of
						<<"password">> -> 
							case ems_util:get_client_request_by_id_and_secret(Request) of
								{ok, Client0} -> 
									log_client_debug(Client0),
									PasswordGrantResult = password_grant(Request, Client0),
									PasswordGrantResult;
								_ -> 
									PasswordGrantResult = password_grant(Request, undefined), % cliente é opcional no grant_type password
									PasswordGrantResult
							end;
						<<"client_credentials">> ->
							case ems_util:get_client_request_by_id_and_secret(Request) of
								{ok, Client0} ->
									log_client_debug(Client0),
									case OAuth2AllowClientCredentials of
										true ->
											ClientCredentialResult = client_credentials_grant(Request, Client0),
											ClientCredentialResult;
										false ->
											{error, access_denied, eoauth2_client_credentials_denied}	
									end;
								{error, ReasonAuthorizationCode, ReasonDetailClientCredential} = Error -> 
									ems_logger:error("ems_oauth2_authorize execute client_credentials failed in get_client_request_by_id_and_secret. Reason: ~p  ReasonDetail: ~p.", [ReasonAuthorizationCode, ReasonDetailClientCredential]),
									Error
							end;
						<<"token">> -> 
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									log_client_debug(Client0),
									TokenResult = authorization_request(Request, Client0),
									TokenResult;
								{error, ReasonAuthorizationCode, ReasonDetailToken} = Error -> 
									ems_logger:error("ems_oauth2_authorize execute token failed in get_client_request_by_id. Reason: ~p  ReasonDetail: ~p.", [ReasonAuthorizationCode, ReasonDetailToken]),
									Error
							end;
						<<"code">> ->	
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									log_client_debug(Client0),
									CodeResult = authorization_request(Request, Client0),
									CodeResult;
								{error, ReasonAuthorizationCode, ReasonDetailCode} = Error -> 
									ems_logger:error("ems_oauth2_authorize execute code failed in get_client_request_by_id. Reason: ~p  ReasonDetail: ~p.", [ReasonAuthorizationCode, ReasonDetailCode]),
									Error
							end;
						<<"authorization_code">> ->	
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									log_client_debug(Client0),
									AuthorizationCodeResult = access_token_request(Request, Client0),
									AuthorizationCodeResult;
								{error, ReasonAuthorizationCode, ReasonDetailAuthorizationCode} = Error -> 
									ems_logger:error("ems_oauth2_authorize execute authorization_code failed in get_client_request_by_id_and_secret. Reason: ~p  ReasonDetail: ~p.", [ReasonAuthorizationCode, ReasonDetailAuthorizationCode]),
									Error
							end;
						<<"refresh_token">> ->	
							case ems_util:get_client_request_by_id(Request) of
								{ok, Client0} -> 
									log_client_debug(Client0),
									RefreshTokenResult = refresh_token_request(Request, Client0),
									RefreshTokenResult;
								{error, ReasonAuthorizationCode, ReasonDetailRefreshToken} = Error -> 
									ems_logger:error("ems_oauth2_authorize execute refresh_token failed in get_client_request_by_id. Reason: ~p  ReasonDetail: ~p.", [ReasonAuthorizationCode, ReasonDetailRefreshToken]),
									Error
							end;
						 _ -> 
							ems_logger:error("ems_oauth2_authorize failed on parse invalid grant_type ~p.", [GrantType]),
							{error, access_denied, einvalid_grant_type}
				end;
			{ok, PassportCodeInt, Client0, User0} ->
				log_client_debug(Client0),
				ems_logger:info("ems_oauth2_authorize autenticate by passport PassportCodeInt: ~p Client: ~p User: ~p.", [PassportCodeInt, Client0, User0]),
				_GrantType = <<"authorization_code">>,
				Result = password_grant_passport(Request, binary_to_list(PassportCodeBinBase64), PassportCodeInt, Client0, User0),
				Result
		end,
		case Result of
			{ok, Response = #response{client = Client, 
									  resource_owner = User,
									  access_token = AccessToken,
									  refresh_token = _RefreshToken}} ->
					case User =/= undefined of
						true -> 
							ok;
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
						true -> 
							{ok, AccessCode} = get_code_by_user_and_client(User, Client, Request),
							spawn(fun() -> 
								persist_token_sgbd(Service, User, Client, AccessCode, AccessToken, Response#response.scope, Response#response.state, UserAgent)
							end);
						false -> ok
					end,
					
					% Lógica OIDC: Gerar id_token se o escopo "openid" estiver presente
					Scopes = binary:split(maps:get(<<"scope">>, Response#response.state, <<>>), <<" ">>, [global]),
					IdTokenPart = case lists:member(<<"openid">>, Scopes) of
						true ->
							% Configura Claims do ID Token
							Config = ems_config:getConfig(),
							Issuer = Config#config.rest_auth_url, % URL do emissor (Identity Provider)
							Subject = case User of
								undefined -> <<"unknown">>;
								#user{id = UserId} -> ems_util:integer_to_binary_def(UserId, 0)
							end,
							Audience = case Client of
								undefined -> <<"unknown">>;
								#client{id = ClientIdComp} -> ems_util:integer_to_binary_def(ClientIdComp, 0)
							end,
							Now = ems_util:get_timestamp(),
							Exp = Now + Response#response.expires_in,
							Claims = #{
								<<"iss">> => Issuer,
								<<"sub">> => Subject,
								<<"aud">> => Audience,
								<<"exp">> => Exp,
								<<"iat">> => Now,
								<<"auth_time">> => Now
							},
							% Assina o token com a chave configurada
							Secret = Config#config.oauth2_jwt_secret,
							IdToken = ems_util:jwt_encode(Claims, Secret),
							iolist_to_binary([<<"\"id_token\":\""/utf8>>, IdToken, <<"\","/utf8>>]);
						false -> <<>>
					end,

					ResponseData2 = iolist_to_binary([<<"{"/utf8>>,
															ClientProp,
														   <<"\"access_token\":\""/utf8>>, Response#response.access_token, <<"\","/utf8>>,
														   <<"\"expires_in\":"/utf8>>, ems_util:integer_to_binary_def(Response#response.expires_in, 0), <<","/utf8>>,
														   <<"\"resource_owner\":"/utf8>>, ResourceOwner, <<","/utf8>>,
														   <<"\"scope\":\""/utf8>>, maps:get(<<"scope">>, Response#response.state, <<>>), <<"\","/utf8>>,
														   <<"\"state\":\""/utf8>>, maps:get(<<"state">>, Response#response.state, <<>>), <<"\","/utf8>>,
														   <<"\"refresh_token\":\""/utf8>>, Response#response.refresh_token, <<"\","/utf8>>, 
														   IdTokenPart,
														   <<"\"refresh_token_in\":"/utf8>>, ems_util:integer_to_binary_def(Response#response.refresh_token_expires_in, 0), <<","/utf8>>,
														   <<"\"token_type\":\""/utf8>>, Response#response.token_type, <<"\""/utf8>>,
													   <<"}"/utf8>>]),
					Request2 = Request#request{code = 200, 
											    reason = ok,
											    response_data = ResponseData2,
											    client = Client,
											    user = User,
											    content_type_out = ?CONTENT_TYPE_JSON},		
					{ok, Request2};		
			{redirect, Client = #client{id = _ClientId, redirect_uri = RedirectUri0}} ->
					Config = ems_config:getConfig(),
					% Se passar a querystring redirect_uri  na url, pega este, senão o valor do atributo redirect_uri do #client
					case ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request) of
						<<>> -> RedirectUri = iolist_to_binary([<<"&redirect_uri=">>, RedirectUri0]);
						undefined -> RedirectUri = iolist_to_binary([<<"&redirect_uri=">>, RedirectUri0]);
						_ -> RedirectUri = <<>>			% não precisa porque já vai estar na QuerystringBin
					end,
					case Config#config.rest_use_host_in_redirect of
						true -> 
							LocationPath = iolist_to_binary([<<"http://"/utf8>>, Host, <<"/login/index.html?">>, QuerystringBin, RedirectUri]);
						false ->
							LocationPath = iolist_to_binary([Config#config.rest_login_url, <<"?">>, QuerystringBin, RedirectUri])
					end,
					ems_logger:info("ems_oauth2_authorize redirect to ~p.", [binary_to_list(LocationPath)]),
					Request2 = Request#request{code = 302, 
											   reason = ok,
											   client = Client,
											   response_header = ResponseHeader#{<<"location">> => LocationPath}
											},
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
											   response_data = ?ACCESS_DENIED_JSON,
											   user = User},
					{error, Request2}
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_oauth2_authorize execute exception. Reason: ~p.", [ReasonException]),
			Request3 = Request#request{code = 401, 
									   reason = access_denied,
									   reason_detail = eparse_oauth2_authorize_execute,
									   user = undefined,
									   client = undefined,
									   response_data = ?ACCESS_DENIED_JSON},
			{error, Request3}
	end.

%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
code_request(Request = #request{response_header = ResponseHeader, querystring = QuerystringBin}) ->
	try
		case ems_util:get_client_request_by_id(Request) of
			{ok, Client} ->
				log_client_debug(Client),
				case ems_util:get_user_request_by_login_and_password(Request, Client) of
					{ok, User} ->
						RedirectUri = ems_util:normalize_url(ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request)),
						case get_code_by_user_and_client(User, Client, Request) of
							{ok, Code} ->
								LocationPath = iolist_to_binary([RedirectUri, <<"?code=">>, Code, <<"&">>, QuerystringBin]),
								%% Retorna 200 com JSON {redirect: ...} para o login.js fazer o redirecionamento
								ResponseData = iolist_to_binary([<<"{\"redirect\":\"">>, LocationPath, <<"\"}">>]),
								Request2 = Request#request{code = 200, 
														   reason = ok,
														   user = User,
														   client = Client,
														   response_data = ResponseData,
														   content_type_out = ?CONTENT_TYPE_JSON,
														   response_header = ResponseHeader#{<<"location">> => LocationPath}},
								{ok, Request2};
							{error, Reason} ->
								Request2 = Request#request{code = 401, 
														   reason = Reason,
														   reason_detail = get_code_by_user_and_client_failed,
														   user = User,
														   client = Client,
														   response_data = ?ACCESS_DENIED_JSON},
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
												   user = User,
												   client = Client,
												   response_data = ?ACCESS_DENIED_JSON},
						{error, Request2}
				end;
			{error, Reason, ReasonDetail} ->
				Request2 = Request#request{code = 401, 
											reason = Reason,
											reason_detail = ReasonDetail,
											user = undefined,
											client = undefined,
											response_data = ?ACCESS_DENIED_JSON},
				{error, Request2}
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_oauth2_authorize code_request exception. Reason: ~p.", [ReasonException]),
			Request3 = Request#request{code = 401, 
										reason = access_denied,
										reason_detail = eparse_code_request_exception,
										user = undefined,
										client = undefined,
										response_data = ?ACCESS_DENIED_JSON},
			{error, Request3}
	end.

user_info(Request = #request{user = User, client = Client}) ->
    try
		io:format("Client#client.id: ~p\n", [Client#client.id]),
		% não vai ser to_resource_owner aqui!!! o json com certeza é diferente
		UserJson = ems_user:get_user_info(User, Client#client.id),
		io:format("UserJson is ~p\n", [UserJson]),
		Request2 = Request#request{code = 200, 
								   reason = ok,
								   response_data = UserJson,
								   content_type_out = ?CONTENT_TYPE_JSON},
		{ok, Request2}
	catch
		_:ReasonException ->
			ems_logger:error("ems_oauth2_authorize user_info exception. Reason: ~p.", [ReasonException]),
			Request3 = Request#request{code = 401, 
										reason = access_denied,
										reason_detail = eparse_user_info_exception,
										user = undefined,
										client = undefined,
										response_data = ?ACCESS_DENIED_JSON},
			{error, Request3}
	end.


	
%%%===================================================================
%%% Funções internas
%%%===================================================================

normalize_grant_type(<<"0">>) -> <<"authorization_code">>;
normalize_grant_type(<<"1">>) -> <<"password">>;
normalize_grant_type(<<"2">>) -> <<"client_credentials">>;
normalize_grant_type(<<"3">>) -> <<"refresh_token">>;
normalize_grant_type(GrantType) -> GrantType.


%% Cliente Credencial Grant- seção 4.4.1 do RFC 6749. 
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=client_credentials&client_id=s6BhdRkqt3&secret=qwer
-spec client_credentials_grant(#request{}, #client{}) -> {ok, list(), #client{}} | {error, access_denied, atom()}.
client_credentials_grant(Request = #request{querystring_map = StateProp}, Client) ->
	try
		case ems_util:get_querystring(<<"scope">>, <<>>, Request) of
			<<>> -> ScopeProp = <<>>;
			undefined -> ScopeProp = <<>>;
			ScopeValue -> ScopeProp = ScopeValue
		end,
		Authz = oauth2:authorize_client_credentials(Client, ScopeProp, StateProp, []),
		issue_token(Authz)
	catch
		_:_ -> {error, access_denied, eparse_client_credentials_grant_exception}
	end.


%% Resource Owner Password Credentials Grant - seção 4.3.1 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=password&username=johndoe&password=A3ddj3w
-spec password_grant(#request{}, #client{}) -> {ok, list(), #client{}} | {error, access_denied, atom()}.
password_grant(Request = #request{querystring_map = StateProp}, Client) -> 
	try
		case ems_util:get_querystring(<<"scope">>, <<>>, Request) of
			<<>> -> ScopeProp = <<>>;
			undefined -> ScopeProp = <<>>;
			ScopeValue -> ScopeProp = ScopeValue
		end,
		case ems_util:get_user_request_by_login_and_password(Request, Client) of
			{ok, User} ->
				case Client == undefined of
					true -> 
						Authz = oauth2:authorize_password(User, ScopeProp, StateProp, []);
					false -> 
						Authz = oauth2:authorize_password(User, Client, ScopeProp, StateProp, [])
				end,
				issue_token(Authz);
			Error -> 
				Error
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_util password_grant exception. Client: ~p. Reason: ~p.", [Client, ReasonException]),
			{error, access_denied, eparse_password_grant_exception}
	end.


-spec password_grant_passport(#request{}, string(), non_neg_integer(), #client{}, #user{}) -> {ok, list(), #client{}} | {error, access_denied, atom()}.
password_grant_passport(Request = #request{querystring_map = StateProp}, PassportCodeBase64, PassportCodeInt, Client, User) -> 
	try
		case ems_util:get_querystring(<<"scope">>, <<>>, Request) of
			<<>> -> ScopeProp = <<>>;
			undefined -> ScopeProp = <<>>;
			ScopeValue -> ScopeProp = ScopeValue
		end,
		case Client == undefined of
			true -> 
				Authz = oauth2:authorize_password(User, ScopeProp, StateProp, []),
				ems_logger:info("ems_oauth2_authorize autenticate passport ~s (~p) user ~p.", [PassportCodeBase64, PassportCodeInt,
																						  integer_to_list(User#user.id) ++ " - " ++ User#user.name]);
			false -> 
				Authz = oauth2:authorize_password(User, Client, ScopeProp, StateProp, []),
				ems_logger:info("ems_oauth2_authorize autenticate passport ~s (~p) client ~p  user ~p.", [PassportCodeBase64, PassportCodeInt,
																									 integer_to_list(Client#client.id) ++ " - " ++ Client#client.name, 
																									 integer_to_list(User#user.id) ++ " - " ++ User#user.name])
		end,
		issue_token(Authz)
	catch
		_:_ -> {error, access_denied, eparse_password_grant_pass_exception}
	end.
	
%% Verifica a URI do Cliente e redireciona para a página de autorização - Implicit Grant e Authorization Code Grant
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html
-spec authorization_request(#request{}, #client{}) -> {ok, list()} | {error, access_denied, atom()}.

authorization_request(Request, Client) ->
    try
		RedirectUri = ems_util:normalize_url(ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request)),
		case ems_oauth2_backend:verify_redirection_uri(Client, RedirectUri, []) of
			{ok, _} -> 
				{redirect, Client};
			_ -> 
				ems_logger:warn("ems_oauth2_authorize authorization_client redirect_uri diferent. Client RedirectUri: \"~s\"  Loader RedirectUri: \"~s\".", 
																																[binary_to_list(RedirectUri), 
				  																											     binary_to_list(Client#client.redirect_uri)]),
				{redirect, Client}
		end
	catch
		_:_ -> {error, access_denied, eparse_authorization_request_exception}
	end.


%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
-spec refresh_token_request(#request{}, #client{}) -> {ok, list()} | {error, access_denied, atom()}.
refresh_token_request(Request = #request{querystring_map = StateProp}, Client) ->
	try
		case ems_util:get_querystring(<<"scope">>, <<>>, Request) of
			<<>> -> ScopeProp = <<>>;
			undefined -> ScopeProp = <<>>;
			ScopeValue -> ScopeProp = ScopeValue
		end,
		case ems_util:get_querystring(<<"refresh_token">>, <<>>, Request) of
			<<>> -> {error, access_denied, erefresh_token_empty};
			RefleshToken ->
				Authz = ems_oauth2_backend:authorize_refresh_token(Client, RefleshToken, ScopeProp, StateProp),
				issue_token(Authz)
		end
	catch
		_:_ -> {error, access_denied, eparse_refresh_token_request_exception}
	end.


%% Requisita o token de acesso com o código de autorização - seções  4.1.3. e  4.1.4 do RFC 6749.
%% Requisita o token de acesso com o código de autorização - seções  4.1.3. e  4.1.4 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=authorization_code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w&secret=qwer&code=dxUlCWj2JYxnGp59nthGfXFFtn3hJTqx
%% NOTA: redirect_uri é OPCIONAL no token request (backward compatible com clientes antigos)
%%       Se enviado, será validado contra o redirect_uri armazenado no authorization code (RFC 6749)
%%       Se não enviado, usa o redirect_uri armazenado (comportamento anterior)
-spec access_token_request(#request{}, #client{}) -> {ok, list()} | {error, access_denied, atom()}.
access_token_request(Request, Client) ->
	try
		% Debug: Print all parameters
		Params = Request#request.querystring_map,
		PayloadMap = Request#request.payload_map,
		ems_logger:debug("ems_oauth2_authorize access_token_request Params: ~p Payload: ~p", [Params, PayloadMap]),

		Code = case ems_util:get_querystring(<<"code">>, <<>>, Request) of
			<<>> -> 
				% Fallback: Check in payload_map (supports JSON body or unmerged body params)
				case PayloadMap of
					#{<<"code">> := CodePayload} -> CodePayload;
					_ -> <<>>
				end;
			CodeVal -> CodeVal
		end,

		case Code of
			<<>> -> 
				{error, access_denied, ecode_empty};
			_ -> 
				% Obtém redirect_uri do request (pode ser vazio, undefined ou um valor)
				RedirectUriFromRequest = ems_util:normalize_url(
					ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request)
				),
				
				% Se redirect_uri foi enviado no request, usa ele para validação
				% Se não foi enviado (<<>> ou undefined), passa vazio para oauth2 usar o armazenado
				RedirectUri = case RedirectUriFromRequest of
					<<>> -> <<>>;      % Não enviado, usa o armazenado (backward compatible)
					undefined -> <<>>; % Não enviado, usa o armazenado (backward compatible)
					Uri -> Uri         % Enviado, valida contra o armazenado (RFC 6749)
				end,
				
				Authz = oauth2:authorize_code_grant(Client, Code, RedirectUri, []),
				issue_token_and_refresh(Authz)
		end
	catch
		_:_ -> {error, access_denied, eparse_access_token_request}
	end.
	

issue_token({ok, {_, Auth}}) ->
	case oauth2:issue_token(Auth, []) of
		{ok, {_, Result}} -> 
			{ok, Result};
		_ -> 
			{error, access_denied, einvalid_issue_token}
	end;
issue_token(Result) -> 
	ems_logger:error("ems_oauth2_authorize issue_token failed. Result: ~p.", [Result]),
	{error, access_denied, einvalid_authorization}.
    

issue_token_and_refresh({ok, {_, Auth}}) ->
	T1 = ems_util:get_timestamp(),
	case oauth2:issue_token_and_refresh(Auth, []) of
		{ok, {_, Result}} -> 
			T2 = ems_util:get_timestamp(),
			ems_logger:info("ems_oauth2_authorize issue_token_and_refresh execution time: ~p ms.", [T2 - T1]),
			{ok, Result};
		_ -> {error, access_denied, einvalid_issue_token_and_refresh}
	end;
issue_token_and_refresh(Result) -> 
	ems_logger:error("ems_oauth2_authorize issue_token_and_refresh failed. Result: ~p.", [Result]),
	{error, access_denied, einvalid_authorization}.


issue_code({ok, {_, Auth}}) ->
	case oauth2:issue_code(Auth, []) of
		{ok, {_, Response}} ->	
			{ok, oauth2_response:to_proplist(Response)};
		_ -> {error, access_denied, einvalid_issue_code}
	end;
issue_code(_) -> {error, access_denied, eparse_issue_code_exception}.


-spec get_code_by_user_and_client(#user{}, #client{}, #request{}) -> {ok, binary()} | {error, enoent}.
get_code_by_user_and_client(User, Client, Request = #request{querystring_map = QuerystringMap}) ->
	RedirectUri = ems_util:get_querystring(<<"redirect_uri">>, <<>>, Request),
	Authz = oauth2:authorize_code_request(User, Client, RedirectUri, undefined, QuerystringMap, []),
	case issue_code(Authz) of
		{ok, ResponseCode} -> {ok, element(2, lists:nth(1, ResponseCode))};
		_ -> {ok, enoent}
	end.


persist_token_sgbd(
				  #service{properties = Props}, 
				  #user{ id = IdUsuario, codigo = IdPessoa, ctrl_source_type = CtrlSourceType }, 
				  #client{name = ClientNameBin}, 
				  AccessCode,
				  AccessToken, 
				  _Scope, 
				  _State,
				  UserAgentBin) ->
	T1 = ems_util:get_timestamp(),
	try

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

						AccessCode2 = binary_to_list(AccessCode),

						ParamsSql = [{{sql_varchar, 32}, [ClientName]},	% Client name
									  {sql_integer, [IdPessoa]},
									  {sql_integer, [IdUsuario]},
									  {{sql_varchar, 32}, [AccessToken2]},					% Token
									  {{sql_varchar, 32}, [AccessCode2]},					% Device ID (Code) 
									  {{sql_varchar, 32}, [format_user_agent_legacy(UserAgentBin)]}],	% Device Info

						ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),

						ems_odbc_pool:release_connection(Ds2),
						ok;
					{error, Reason} ->
						ems_logger:error("ems_oauth2_authorize persist_token_sgbd failed to get database connection. AccessCode: ~p AccessToken: ~p. Reason: ~p.", [AccessCode, AccessToken, Reason])
				end;
			false -> 
				ok
		end,
		T2 = ems_util:get_timestamp(),
		ems_logger:info("ems_oauth2_authorize persist_token_sgbd execution time: ~p ms.", [T2 - T1]),
		ok
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_authorize persist_token_sgbd exception. AccessCode: ~p AccessToken: ~p. Reason: ~p.", [AccessCode, AccessToken, ReasonException]),
			% vai ignorar o erro 
			ok
	end.


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
				ems_logger:info("ems_oauth2_authorize parse_passport_code finding passport code ~s (~s)...", [PassportCodeBinBase64Str, PassportCodeStr2]),
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
								ems_logger:error("ems_oauth2_authorize parse_passport_code failed to find client of passport ~s (~s).", [PassportCodeBinBase64Str, PassportCodeStr2]),
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

log_client_debug(Client) ->
	case ems_logger:in_debug() andalso Client =/= undefined of
		true -> 
			ems_logger:info("ems_oauth2_authorize client debug details: ~p.", [Client]);
		false -> ok
	end.

format_user_agent_legacy(UserAgentBin) ->
	{Atom, Version} = parse_user_agent_legacy(UserAgentBin),
	atom_to_list(Atom) ++ " " ++ binary_to_list(Version).

parse_user_agent_legacy(UserAgentBin) ->
	UA = string:to_lower(binary_to_list(UserAgentBin)),
	case string:str(UA, "chrome") > 0 of
		true -> {chrome, parse_version(UA, "chrome/")};
		false ->
			case string:str(UA, "firefox") > 0 of
				true -> {firefox, parse_version(UA, "firefox/")};
				false ->
				   case string:str(UA, "safari") > 0 of
						true -> {safari, parse_version(UA, "version/")}; 
						false ->
							case string:str(UA, "opera") > 0 orelse string:str(UA, "opr") > 0 of
								true -> {opera, parse_version(UA, "opr/")};
								false -> {others, <<"0.0">>}
							end
				   end
			end
	end.

parse_version(UA, Token) ->
	case string:str(UA, Token) of
		0 -> <<"0.0">>;
		Index ->
			Start = Index + length(Token) - 1,
			Rest = string:substr(UA, Start + 1),
			case string:tokens(Rest, " ;") of
				[Ver | _] -> list_to_binary(Ver);
				_ -> <<"0.0">>
			end
	end.
