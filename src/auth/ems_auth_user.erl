%%********************************************************************
%% @title Module ems_auth_user
%% @version 1.0.0
%% @doc Module responsible for authenticating users.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_auth_user).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
    
-export([authenticate/2]).

-spec authenticate(#service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied, atom()}.
authenticate(Service = #service{authorization = AuthorizationMode,
							     authorization_public_check_credential = AuthorizationPublicCheckCredential}, 
			 Request = #request{type = Type}) ->
	try
		put(authenticate, authenticate_step_pass1),
		case Type of
			<<"OPTIONS">> -> 
				{ok, public, public, <<>>, <<>>, <<>>};
			"HEAD" -> 
				{ok, public, public, <<>>, <<>>, <<>>};
			_ -> 
				put(authenticate, authenticate_step_pass2),
				case AuthorizationMode of
					basic -> 
						do_basic_authorization(Service, Request);
					oauth2 -> 
						do_bearer_authorization(Service, Request);
					_ -> 	% public
						put(authenticate, authenticate_step_pass3),
						case AuthorizationPublicCheckCredential of
							true ->
								put(authenticate, authenticate_step_pass4),
								case do_basic_authorization(Service, Request) of
									{ok, Client, User, AccessToken, Scope, State} -> 
										{ok, Client, User, AccessToken, Scope, State};
									_ -> 
										{ok, public, public, <<>>, <<>>, <<>>}
								end;
							false -> 
								put(authenticate, authenticate_step_pass5),
								{ok, public, public, <<>>, <<>>, <<>>}
						end
				end
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user authenticate exception. Request: ~p. Reason: ~p.", [Request, ReasonException]),
			{error, access_denied, eauthenticate_failed}
	end.


%%====================================================================
%% Internal functions
%%====================================================================

-spec do_basic_authorization(#service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied, atom()}.
do_basic_authorization(Service, Request = #request{authorization = <<>>}) -> 
	do_bearer_authorization(Service, Request);
do_basic_authorization(Service = #service{auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials}, Request = #request{authorization = Authorization}) ->
	try
		case ems_util:get_client_request_by_id(Request) of
			{ok, ClientFound} -> 
				ClientName = binary_to_list(ClientFound#client.name),
				Client = ClientFound;
			_ -> 
				ClientName = "public",
				Client = public
		end,
		case ems_util:parse_basic_authorization_header(Authorization) of
			{ok, Login, Password} ->
				case ems_user:find_by_login_and_password(Login, Password) of
					{ok, User = #user{active = Active, ctrl_source_type = Table}} -> 
						case Active orelse AuthAllowUserInativeCredentials of
							true -> 
								ems_logger:info("ems_auth_user do_basic_authorization success for login: ~s, name: ~s, authorization: ~p, CtrlSourceTable: ~p, client: ~s.", [Login, binary_to_list(User#user.name), binary_to_list(Authorization), Table, ClientName]),
								case ems_util:get_querystring(<<"state">>, <<>>, Request) of
									<<>> -> StateProp = <<>>;
									undefined -> StateProp = <<>>;
									StateValue -> StateProp = StateValue
								end,
								case ems_util:get_querystring(<<"scope">>, <<>>, Request) of
									<<>> -> ScopeProp = <<>>;
									undefined -> ScopeProp = <<>>;
									ScopeValue -> ScopeProp = ScopeValue
								end,
								do_check_grant_permission(Service, Request, Client, User, ScopeProp, StateProp, atom_to_binary(Table, utf8), basic);
							false -> 
								ems_logger:error("ems_auth_user do_basic_authorization denied for inative_user: ~s, authorization: ~p, CtrlSourceTable: ~p, client: ~s.", [Login, binary_to_list(Authorization), Table, ClientName]),
								{error, access_denied, einative_user}
						end;
					Error -> 
						ems_logger:error("ems_auth_user do_basic_authorization denied for invalid login or password, authorization: ~p, login: ~p, client: ~p.", [binary_to_list(Authorization), Login, ClientName]),
						Error
				end;
			{error, access_denied, ebasic_authorization_header_required} -> 
				do_bearer_authorization(Service, Request); % Se o header não é Basic, então tenta oauth2
			Error -> 
				ems_logger:error("ems_auth_user do_basic_authorization failed on parse header authorizatoin: ~s and client: ~s.", [binary_to_list(Authorization), ClientName]),
				Error
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user do_basic_authorization failed. Reason: ~p.", [ReasonException]),
			{error, access_denied, edo_basic_authorization_failed}
	end.


-spec do_bearer_authorization(#service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied, atom()}.
do_bearer_authorization(Service, Request = #request{authorization = <<>>}) ->
	AccessToken = ems_util:get_querystring(<<"token">>, <<"access_token">>, <<>>, Request),
	do_oauth2_check_access_token(AccessToken, Service, Request);
do_bearer_authorization(Service, Request = #request{authorization = Authorization}) ->	
	try
		case ems_util:parse_bearer_authorization_header(Authorization) of
			{ok, AccessToken} -> 
				ems_logger:info("ems_auth_user do_bearer_authorization success for authorization: ~p, AccessToken: ~p.", [binary_to_list(Authorization), AccessToken]),
				do_oauth2_check_access_token(AccessToken, Service, Request);
			Error -> 
				ems_logger:error("ems_auth_user do_bearer_authorization failed on parse authorization: ~p.", [binary_to_list(Authorization)]),

				Error
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user do_bearer_authorization failed. Reason: ~p.", [ReasonException]),
			{error, access_denied, edo_bearer_authorization_failed}
	end.
		

-spec do_oauth2_check_access_token(binary(), #service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied}.
do_oauth2_check_access_token(<<>>, _, _) -> 

	{error, access_denied, eaccess_token_required};
do_oauth2_check_access_token(AccessToken, Service, Req) ->
	try
		case byte_size(AccessToken) > 32 of
			true -> 
				ems_logger:error("ems_auth_user do_oauth2_check_access_token failed due invalid token length, AccessToken: ~p, referer: ~s.", [AccessToken, binary_to_list(Req#request.referer)]),

				{error, access_denied, einvalid_access_token_size};
			false -> 
				case oauth2:verify_access_token(AccessToken, undefined) of
					{ok, {[], [{<<"client">>, Client}, 
							   {<<"resource_owner">>, User}, 
							   {<<"expiry_time">>, _ExpityTime}, 
							   {<<"scope">>, Scope},
							   {<<"state">>, State}]}} -> 
						% Não é aceito um token gerado em um browser ser utilizado em outro browser
						case Client =/= undefined of
							true ->
									case Client#client.user_agent =:= Req#request.user_agent  of 
											true ->
												ems_logger:info("ems_auth_user do_oauth2_check_access_token success peer: ~s , user-agent: ~s, forwarded-for: ~s for access token: ~s, user login: ~s, client: ~s, token peer: ~s, token user-agent: ~p, token forwarded-for: ~p, referer: ~s.", [binary_to_list(Req#request.ip_bin), Req#request.user_agent, binary_to_list(Req#request.forwarded_for), binary_to_list(AccessToken), binary_to_list(User#user.login), binary_to_list(Client#client.name),  binary_to_list(Client#client.peer), Client#client.user_agent, binary_to_list(Client#client.forwarded_for), binary_to_list(Req#request.referer)]),
												do_check_grant_permission(Service, Req, Client, User, AccessToken, Scope, State, oauth2);
											false ->
												ems_logger:error("ems_auth_user do_oauth2_check_access_token denied invalid peer: ~s , user-agent: ~s, forwarded-for: ~s for access token: ~s, user login: ~s, client: ~s, token peer: ~s, token user-agent: ~p, token forwarded-for: ~p, referer: ~s.", [binary_to_list(Req#request.ip_bin), Req#request.user_agent, binary_to_list(Req#request.forwarded_for), binary_to_list(AccessToken), binary_to_list(User#user.login), binary_to_list(Client#client.name),  binary_to_list(Client#client.peer), Client#client.user_agent, binary_to_list(Client#client.forwarded_for), binary_to_list(Req#request.referer)]),

												{error, access_denied, einvalid_peer_token}
									end;
							false ->
									do_check_grant_permission(Service, Req, public, User, AccessToken, Scope, State, oauth2)
						end;
				_ -> 
					ems_logger:error("ems_auth_user do_oauth2_check_access_token denied invalid access token for AccessToken: ~p, referer: ~s.", [AccessToken, binary_to_list(Req#request.referer)]),

					{error, access_denied, einvalid_access_token}
				end
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user do_oauth2_check_access_token failed. Reason: ~p.", [ReasonException]),
			{error, access_denied, edo_oauth2_check_access_token_failed}
	end.
	

-spec do_check_grant_permission(#service{}, #request{}, #client{} | public, #user{}, binary(), binary(), binary(), atom()) -> {ok, #client{}, #user{}, binary(), binary()} | {error, access_denied}.
do_check_grant_permission(Service = #service{name = ServiceName, 
											 restricted = RestrictedService, 
											 owner = Owner}, 
						  Req, 
						  Client, 
						  User = #user{admin = Admin}, 
						  AccessToken, 
						  Scope, 
						  State, 
						  _) ->
	try
		case Client of
			public -> 
				ClientName = "public",
				AuthorizationOwner = [];
			_ ->
				ClientName = binary_to_list(Client#client.name),
				AuthorizationOwner = Client#client.authorization_owner
		end,
		OwnerStr = binary_to_list(Owner),
		% Para consumir o serviço deve obedecer as regras
		% ===================================================================
		% O usuário é administrador e pode consumir qualquer serviço
		% Não é administrador e possui permissão em serviços não restritos a administradores e o cliente tem permissão para consumir os ws do owner
		PermiteAcessarComoAdmin = Admin,
		case AuthorizationOwner =:= <<>> orelse AuthorizationOwner == undefined of
			true -> 
				AuthorizationOwnerStr = "",
				PermiteAcessarWebserviceDoOwner = true;
			false ->
				case PermiteAcessarComoAdmin of
					false -> 
						PermiteAcessarServicoNaoRestritoComoUserNormal = not RestrictedService andalso ems_user_permission:has_grant_permission(Service, Req, User),
						case PermiteAcessarServicoNaoRestritoComoUserNormal of
							true ->
								PermiteAcessarWebserviceDoOwner = AuthorizationOwner == [] orelse lists:member(Owner, AuthorizationOwner);
							false ->
								PermiteAcessarWebserviceDoOwner = false
						end;
					true -> 
						PermiteAcessarWebserviceDoOwner = true
				end,
				AuthorizationOwnerStr = string:join(ems_util:binlist_to_list(AuthorizationOwner), ",")
		end,
		case PermiteAcessarWebserviceDoOwner of 
			false -> PermiteAcessarWsOAuth2 = ServiceName =:= <<"/authorize">> orelse ServiceName =:= <<"/code_request">> orelse ServiceName =:= <<"/resource">>;   
			true -> PermiteAcessarWsOAuth2 = true
		end,
		case PermiteAcessarComoAdmin orelse PermiteAcessarWebserviceDoOwner orelse PermiteAcessarWsOAuth2 of
			true -> 
				case not RestrictedService of
					true ->
						case PermiteAcessarComoAdmin of
							true -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for service: ~s, admin user login: ~s, is_admin: ~p, client: ~s, owner: ~s, authorization_owner: ~p.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr]);
							false -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for service: ~s, user login: ~s, is_admin: ~p, client: ~s, owner: ~s, authorization_owner: ~p.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr])
						end;
					false ->
						case PermiteAcessarComoAdmin of
							true -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for restricted service: ~s, admin user login: ~s, client: ~s, owner: ~s, authorization_owner: ~p.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), ClientName, OwnerStr, AuthorizationOwnerStr]);
							false -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for restricted service: ~s, user login: ~s, client: ~s, owner: ~s, authorization_owner: ~p.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), ClientName, OwnerStr, AuthorizationOwnerStr])
						end
				end,
				{ok, Client, User, AccessToken, Scope, State};
			false -> 

				case not RestrictedService of
					true -> ems_logger:error("ems_auth_user do_check_grant_permission denied grant for service: ~s, user login: ~s, is_admin: ~p, client: ~s, owner: ~s, authorization_owner: ~p.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr]);
					false -> ems_logger:error("ems_auth_user do_check_grant_permission denied grant for restricted service: ~s, user login: ~s, is_admin: ~p, client: ~s, owner: ~s, authorization_owner: ~p.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr])
				end,
				case RestrictedService of
					true ->	{error, access_denied, erestricted_service};
					false -> {error, access_denied, eno_grant_permission}
				end
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user do_check_grant_permission failed. Reason: ~p.", [ReasonException]),
			{error, access_denied, edo_check_grant_permission}
	end.
		


