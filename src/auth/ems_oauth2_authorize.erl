-module(ems_oauth2_authorize).

-export([execute/1]).
-export([code_request/1]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").



execute(Request = #request{type = Type, protocol_bin = Protocol, port = Port, host = Host}) -> 
	GrantType = case Type of
		"GET" ->  ems_request:get_querystring(<<"response_type">>, <<>>, Request);
		"POST" -> ems_request:get_querystring(<<"grant_type">>, <<>>, Request)
	end,
    Result = case GrantType of
			<<"password">> -> 
				password_grant(Request);
			<<"client_credentials">> ->
				client_credentials_grant(Request);
			<<"token">> -> 
				authorization_request(Request);
			<<"code">> ->	
				authorization_request(Request);	
			<<"authorization_code">> ->	
				access_token_request(Request);
			<<"refresh_token">> ->	
				refresh_token_request(Request);	
			 _ -> {error, access_denied}
	end,  

	case Result of
		{ok, [{<<"access_token">>,AccessToken},
			   {<<"expires_in">>, ExpireIn},
			   {<<"resource_owner">>, User},
			   {<<"scope">>, Scope},
			   {<<"refresh_token">>, RefreshToken},
			   {<<"refresh_token_expires_in">>, RefreshTokenExpireIn},
			   {<<"token_type">>, TokenType}]
			} ->
				
			ResourceOwner = ems_user:to_resource_owner(User),
			ResponseData2 = iolist_to_binary([<<"{"/utf8>>,
												   <<"\"access_token\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, AccessToken, <<"\""/utf8>>, <<","/utf8>>,
												   <<"\"expires_in\""/utf8>>, <<":"/utf8>>, integer_to_binary(ExpireIn), <<","/utf8>>,
												   <<"\"resource_owner\""/utf8>>, <<":"/utf8>>, ResourceOwner, <<","/utf8>>,
												   <<"\"scope\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, Scope, <<"\""/utf8>>, <<","/utf8>>,
												   <<"\"refresh_token\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, case RefreshToken of
																													undefined -> <<>>;
																													_ -> RefreshToken
																											  end, <<"\""/utf8>>, <<","/utf8>>,
												   <<"\"refresh_token_in\""/utf8>>, <<":"/utf8>>, case RefreshTokenExpireIn of 
																										undefined -> <<"0">>; 
																										_ -> integer_to_binary(RefreshTokenExpireIn) 
																								  end, <<","/utf8>>,
												   <<"\"token_type\""/utf8>>, <<":"/utf8>>, <<"\""/utf8>>, TokenType, <<"\""/utf8>>,
											   <<"}"/utf8>>]),
			{ok, Request#request{code = 200, 
								 response_data = ResponseData2,
								 oauth2_grant_type = GrantType,
								 oauth2_access_token = AccessToken,
								 oauth2_refresh_token = RefreshToken,
								 content_type = <<"application/json;charset=UTF-8">>}
			};		
		{redirect, ClientId, RedirectUri} ->
			LocationPath = iolist_to_binary([Protocol,<<"://"/utf8>>, Host, <<":"/utf8>>,list_to_binary(integer_to_list(Port)),<<"/login/index.html?response_type=code&client_id=">>, ClientId, <<"&redirect_uri=">>, RedirectUri]),
			{ok, Request#request{code = 302, 
								 oauth2_grant_type = GrantType,
								 response_header = #{
														<<"location">> => LocationPath
													}
								}
			};
		Error ->
			ResponseData = ems_schema:to_json(Error),
			{ok, Request#request{code = 401, 
								 oauth2_grant_type = GrantType,
								 response_data = ResponseData}
			}

	end.
%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w
	
code_request(Request = #request{authorization = Authorization}) ->
    ClientId    = ems_request:get_querystring(<<"client_id">>, <<>>, Request),
    RedirectUri = ems_request:get_querystring(<<"redirect_uri">>, <<>>, Request),
    State      = ems_request:get_querystring(<<"state">>, <<>>, Request),
    Scope       = ems_request:get_querystring(<<"scope">>, <<>>,Request),
    case ems_util:parse_basic_authorization_header(Authorization) of
		{ok, Username, Password} ->
		    Authz = oauth2:authorize_code_request({Username,list_to_binary(Password)}, ClientId, RedirectUri, Scope, []),
			case issue_code(Authz) of
				{ok, Response} ->
					Code = element(2,lists:nth(1,Response)),
					LocationPath = <<RedirectUri/binary,"?code=", Code/binary,"&state=",State/binary>>,
					{ok, Request#request{code = 200, 
						%response_data = <<"code=", Code/binary>>,
						response_data = <<"{}">>,
						response_header = #{
											<<"location">> => LocationPath
											}
						}
					};
				_ ->
					{error, Request#request{code = 400, 
											reason = ecode_request_issue_code}
							}
			end;
		{error, Reason} ->
					{error, Request#request{code = 400, 
											reason = Reason}
							}
		end.

	
%%%===================================================================
%%% Funções internas
%%%===================================================================


%% Cliente Credencial Grant- seção 4.4.1 do RFC 6749. 
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=client_credentials&client_id=s6BhdRkqt3&secret=qwer
client_credentials_grant(Request = #request{authorization = Authorization}) ->
	ClientId = ems_request:get_querystring(<<"client_id">>, <<>>, Request),
	Scope = ems_request:get_querystring(<<"scope">>, <<>>, Request),	
	% O ClientId também pode ser passado via header Authorization
	case ClientId == <<>> of
		true -> 
			case Authorization =/= undefined of
				true ->
					case ems_util:parse_basic_authorization_header(Authorization) of
						{ok, Login, Password} ->
							ClientId2 = list_to_binary(Login),
							Secret = list_to_binary(Password),
							Auth = oauth2:authorize_client_credentials({ClientId2, Secret}, Scope, []),
							issue_token(Auth);
						Error -> Error
					end;
				false -> {error, einvalid_client_credentials}
			end;
		false -> 			
			Secret = ems_request:get_querystring(<<"client_secret">>, <<>>, Request),
			Auth = oauth2:authorize_client_credentials({ClientId, Secret}, Scope, []),
			issue_token(Auth)
	end.

%% Resource Owner Password Credentials Grant - seção 4.3.1 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=password&username=johndoe&password=A3ddj3w
password_grant(Request) -> 
	Username = ems_request:get_querystring(<<"username">>, <<>>, Request),
	Password = ems_request:get_querystring(<<"password">>, <<>>, Request),
	Scope = ems_request:get_querystring(<<"scope">>, <<>>, Request),	
	Authorization = oauth2:authorize_password({Username, Password}, Scope, []),
	issue_token(Authorization).
	
%% Verifica a URI do Cliente e redireciona para a página de autorização - Implicit Grant e Authorization Code Grant
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html

    
authorization_request(Request) ->
    %Scope = ems_request:get_querystring(<<"scope">>, <<>>, Request),
    ClientId = ems_request:get_querystring(<<"client_id">>, <<>>, Request),
    %State = ems_request:get_querystring(<<"state">>, <<>>, Request),
    RedirectUri = ems_request:get_querystring(<<"redirect_uri">>, <<>>, Request),
    Resposta = case ems_oauth2_backend:verify_redirection_uri(ClientId, RedirectUri, []) of
		{ok,_} -> 	{redirect, ClientId, RedirectUri};
		Error -> 	Error
	end,
    Resposta.

%% Requisita o código de autorização - seções 4.1.1 e 4.1.2 do RFC 6749.
%% URL de teste: GET http://127.0.0.1:2301/authorize?response_type=code2&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w


refresh_token_request(Request) ->
    ClientId    = ems_request:get_querystring(<<"client_id">>, <<>>, Request),
    ClientSecret = ems_request:get_querystring(<<"client_secret">>, <<>>, Request),
	Reflesh_token = ems_request:get_querystring(<<"refresh_token">>, <<>>, Request),
	Scope    = ems_request:get_querystring(<<"scope">>, <<>>, Request),
	Authorization = ems_oauth2_backend:authorize_refresh_token({ClientId, ClientSecret}, Reflesh_token, Scope),
    issue_token(Authorization).  

%% Requisita o token de acesso com o código de autorização - seções  4.1.3. e  4.1.4 do RFC 6749.
%% URL de teste: POST http://127.0.0.1:2301/authorize?grant_type=authorization_code&client_id=s6BhdRkqt3&state=xyz%20&redirect_uri=http%3A%2F%2Flocalhost%3A2301%2Fportal%2Findex.html&username=johndoe&password=A3ddj3w&secret=qwer&code=dxUlCWj2JYxnGp59nthGfXFFtn3hJTqx
access_token_request(Request = #request{authorization = Authorization}) ->
	Code = ems_request:get_querystring(<<"code">>, <<>>, Request),
	ClientId    = ems_request:get_querystring(<<"client_id">>, <<>>, Request),
    RedirectUri = ems_request:get_querystring(<<"redirect_uri">>, <<>>, Request),
    ClientSecret = ems_request:get_querystring(<<"client_secret">>, <<>>, Request),
    case ClientSecret == <<>> of
		true -> 
			case Authorization =/= undefined of
				true ->
					case ems_util:parse_basic_authorization_header(Authorization) of
						{ok, Login, Password} ->
							ClientId2 = list_to_binary(Login),
							Secret = list_to_binary(Password),
							Auth = oauth2:authorize_code_grant({ClientId2, Secret}, Code, RedirectUri, []),
							issue_token_and_refresh(Auth);						
						_Error -> {error, invalid_request}
					end;
				false -> {error, einvalid_request}
			end;
		false -> 
			Authz = oauth2:authorize_code_grant({ClientId, ClientSecret}, Code, RedirectUri, []),
			issue_token_and_refresh(Authz)
		end.  

		

issue_token({ok, {_, Auth}}) ->
	{ok, {_, {response, AccessToken, 
						undefined,
						ExpiresIn,
						User,
						Scope, 
						RefreshToken, 
						RefreshTokenExpiresIn,
						TokenType
             }
		}} = oauth2:issue_token(Auth, []),
		
	{ok, [{<<"access_token">>, AccessToken},
            {<<"expires_in">>, ExpiresIn},
            {<<"resource_owner">>, User},
            {<<"scope">>, Scope},
            {<<"refresh_token">>, RefreshToken},
            {<<"refresh_token_expires_in">>, RefreshTokenExpiresIn},
            {<<"token_type">>, TokenType}]};

issue_token(Error) ->
    Error.
    

issue_token_and_refresh({ok, {_, Auth}}) ->
	{ok, {_, {response, AccessToken, 
						undefined,
						ExpiresIn,
						User,
						Scope, 
						RefreshToken, 
						RefreshTokenExpiresIn,
						TokenType
             }
		}} = oauth2:issue_token_and_refresh(Auth, []),
		
	{ok, [{<<"access_token">>, AccessToken},
            {<<"expires_in">>, ExpiresIn},
            {<<"resource_owner">>, User},
            {<<"scope">>, Scope},
            {<<"refresh_token">>, RefreshToken},
            {<<"refresh_token_expires_in">>, RefreshTokenExpiresIn},
            {<<"token_type">>, TokenType}]};
issue_token_and_refresh(Error) ->
    Error.

issue_code({ok, {_, Auth}}) ->
	{ok, {_, Response}} = oauth2:issue_code(Auth, []),
	{ok, oauth2_response:to_proplist(Response)};
issue_code(Error) ->
    Error.