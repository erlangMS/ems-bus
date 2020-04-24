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
		io:format("a1\n"),
		case Type of
			<<"OPTIONS">> -> 
				io:format("a2\n"),
				ems_db:inc_counter(ems_auth_user_public_success),
				{ok, public, public, <<>>, <<>>};
			"HEAD" -> 
				io:format("a3\n"),
				ems_db:inc_counter(ems_auth_user_public_success),
				{ok, public, public, <<>>, <<>>};
			_ -> 
				io:format("a4\n"),
				case AuthorizationMode of
					basic -> 
						io:format("a4.1\n"),
						do_basic_authorization(Service, Request);
					oauth2 -> 
						io:format("a4.2\n"),
						do_bearer_authorization(Service, Request);
					_ -> 
						io:format("a4.3\n"),
						case AuthorizationPublicCheckCredential of
							true ->
								io:format("a4.4\n"),
								case do_basic_authorization(Service, Request) of
									{ok, Client, User, AccessToken, Scope} -> 
										{ok, Client, User, AccessToken, Scope};
									_ -> 
										{ok, public, public, <<>>, <<>>}
								end;
							false -> 
								io:format("a4.5\n"),
								ems_db:inc_counter(ems_auth_user_public_success),
								{ok, public, public, <<>>, <<>>}
						end
				end
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user authenticate failed. Reason: ~p.", [ReasonException]),
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
		io:format("do_basic_authorization1\n"),
		case ems_util:get_client_request_by_id(Request) of
			{ok, ClientFound} -> 
				ClientName = binary_to_list(ClientFound#client.name),
				Client = ClientFound;
			_ -> 
				ClientName = "public",
				Client = public
		end,
		io:format("do_basic_authorization2\n"),
		case ems_util:parse_basic_authorization_header(Authorization) of
			{ok, Login, Password} ->
				case ems_user:find_by_login_and_password(Login, Password) of
					{ok, User = #user{active = Active, ctrl_source_type = Table}} -> 
						case Active orelse AuthAllowUserInativeCredentials of
							true -> 
								ems_logger:info("ems_auth_user do_basic_authorization success for \033[0;32mlogin\033[0m: \033[01;34m~s\033[0m, \033[0;32mname\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization\033[0m: \033[01;34m~p\033[0m, \033[0;32mCtrlSourceTable\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m.", [Login, binary_to_list(User#user.name), binary_to_list(Authorization), Table, ClientName]),
								do_check_grant_permission(Service, Request, Client, User, <<>>, atom_to_binary(Table, utf8), basic);
							false -> 
								ems_logger:error("ems_auth_user do_basic_authorization denied for \033[0;32minative_user\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization\033[0m: \033[01;34m~p\033[0m, \033[0;32mCtrlSourceTable\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m.", [Login, binary_to_list(Authorization), Table, ClientName]),
								{error, access_denied, einative_user}
						end;
					Error -> 
						ems_logger:error("ems_auth_user do_basic_authorization denied for \033[0;32minvalid login or password\033[0m, \033[0;32mauthorization\033[0m: \033[01;34m~p\033[0m, \033[0;32mlogin\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Authorization), Login, ClientName]),
						Error
				end;
			{error, access_denied, ebasic_authorization_header_required} -> 
				do_bearer_authorization(Service, Request); % Se o header não é Basic, então tenta oauth2
			Error -> 
				ems_logger:error("ems_auth_user do_basic_authorization failed on parse header \033[0;32mauthorizatoin\033[0m: \033[01;34m~s\033[0m and \033[0;32mclient\033[0m: \033[01;34m~s\033[0m.", [binary_to_list(Authorization), ClientName]),
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
	io:format("do_bearer_authorization1\n"),
	try
		case ems_util:parse_bearer_authorization_header(Authorization) of
			{ok, AccessToken} -> 
				io:format("do_bearer_authorization2\n"),
				ems_logger:info("ems_auth_user do_bearer_authorization success for \033[0;32mauthorization\033[0m: \033[01;34m~p\033[0m, \033[0;32mAccessToken\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Authorization), AccessToken]),
				do_oauth2_check_access_token(AccessToken, Service, Request);
			Error -> 
				io:format("do_bearer_authorization3\n"),
				ems_logger:error("ems_auth_user do_bearer_authorization failed on parse \033[0;32mauthorization\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Authorization)]),
				ems_db:inc_counter(ems_auth_user_oauth2_denied),
				Error
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user do_bearer_authorization failed. Reason: ~p.", [ReasonException]),
			{error, access_denied, edo_bearer_authorization_failed}
	end.
		

-spec do_oauth2_check_access_token(binary(), #service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied}.
do_oauth2_check_access_token(<<>>, _, _) -> 
	ems_db:inc_counter(ems_auth_user_oauth2_denied),
	{error, access_denied, eaccess_token_required};
do_oauth2_check_access_token(AccessToken, Service, Req) ->
	io:format("do_oauth2_check_access_token1\n"),
	try
		case byte_size(AccessToken) > 32 of
			true -> 
				io:format("do_oauth2_check_access_token2\n"),
				ems_logger:error("ems_auth_user do_oauth2_check_access_token failed due \033[0;32minvalid token length\033[0m, \033[0;32mAccessToken\033[0m: \033[01;34m~p\033[0m, \033[0;32mreferer\033[0m: \033[01;34m~s\033[0m.", [AccessToken, binary_to_list(Req#request.referer)]),
				ems_db:inc_counter(ems_auth_user_oauth2_denied),
				{error, access_denied, einvalid_access_token_size};
			false -> 
				io:format("do_oauth2_check_access_token3\n"),
				case oauth2:verify_access_token(AccessToken, undefined) of
					{ok, {[], [{<<"client">>, Client}, 
							   {<<"resource_owner">>, User}, 
							   {<<"expiry_time">>, _ExpityTime}, 
							   {<<"scope">>, Scope}]}} -> 
						io:format("do_oauth2_check_access_token3.0\n"),
						% Não é aceito um token gerado em um browser ser utilizado em outro browser
						case Client =/= undefined of
							true ->
								io:format("do_oauth2_check_access_token3.1.true\n"),
									case Client#client.user_agent =:= Req#request.user_agent  of 
											true ->
												io:format("do_oauth2_check_access_token3.4\n"),
												%ems_logger:info("ems_auth_user do_oauth2_check_access_token success \033[0;32mpeer\033[0m: \033[01;34m~s\033[0m \033[0;32m, user-agent\033[0m: \033[01;34m~s\033[0m, \033[0;32mforwarded-for\033[0m: \033[01;34m~s\033[0m \033[0;32mfor access token\033[0m: \033[01;34m~s\033[0m, \033[0;32muser login\033[0m: \033[01;34m~s\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mtoken peer\033[0m: \033[01;34m~s\033[0m, \033[0;32mtoken user-agent\033[0m: \033[01;34m~p\033[0m, \033[0;32mtoken forwarded-for\033[0m: \033[01;34m~p\033[0m, \033[0;32mreferer\033[0m: \033[01;34m~s\033[0m.", [binary_to_list(Req#request.ip_bin), Req#request.user_agent, binary_to_list(Req#request.forwarded_for), binary_to_list(AccessToken), binary_to_list(User#user.login), binary_to_list(Client#client.name),  binary_to_list(Client#client.peer), Client#client.user_agent, binary_to_list(Client#client.forwarded_for), binary_to_list(Req#request.referer)]),
												do_check_grant_permission(Service, Req, Client, User, AccessToken, Scope, oauth2);
											false ->
												io:format("do_oauth2_check_access_token3.5\n"),
												%ems_logger:error("ems_auth_user do_oauth2_check_access_token denied invalid \033[0;32mpeer\033[0m: \033[01;34m~s\033[0m \033[0;32m, user-agent\033[0m: \033[01;34m~s\033[0m, \033[0;32mforwarded-for\033[0m: \033[01;34m~s\033[0m \033[0;32mfor access token\033[0m: \033[01;34m~s\033[0m, \033[0;32muser login\033[0m: \033[01;34m~s\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mtoken peer\033[0m: \033[01;34m~s\033[0m, \033[0;32mtoken user-agent\033[0m: \033[01;34m~p\033[0m, \033[0;32mtoken forwarded-for\033[0m: \033[01;34m~p\033[0m, \033[0;32mreferer\033[0m: \033[01;34m~s\033[0m.", [binary_to_list(Req#request.ip_bin), Req#request.user_agent, binary_to_list(Req#request.forwarded_for), binary_to_list(AccessToken), binary_to_list(User#user.login), binary_to_list(Client#client.name),  binary_to_list(Client#client.peer), Client#client.user_agent, binary_to_list(Client#client.forwarded_for), binary_to_list(Req#request.referer)]),
												ems_db:inc_counter(einvalid_peer_token),
												{error, access_denied, einvalid_peer_token}
									end;
							false ->
									io:format("do_oauth2_check_access_token3.1.false\n"),
									do_check_grant_permission(Service, Req, public, User, AccessToken, Scope, oauth2)
						end;
				_ -> 
					io:format("do_oauth2_check_access_token4\n"),
					ems_logger:error("ems_auth_user do_oauth2_check_access_token denied invalid access token for \033[0;32mAccessToken\033[0m: \033[01;34m~p\033[0m, \033[0;32mreferer\033[0m: \033[01;34m~s\033[0m.", [AccessToken, binary_to_list(Req#request.referer)]),
					ems_db:inc_counter(ems_auth_user_oauth2_denied),
					io:format("do_oauth2_check_access_token5\n"),
					{error, access_denied, einvalid_access_token}
				end
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_auth_user do_oauth2_check_access_token failed. Reason: ~p.", [ReasonException]),
			{error, access_denied, edo_oauth2_check_access_token_failed}
	end.
	

-spec do_check_grant_permission(#service{}, #request{}, #client{} | public, #user{}, binary(), binary(), atom()) -> {ok, #client{}, #user{}, binary(), binary()} | {error, access_denied}.
do_check_grant_permission(Service = #service{name = ServiceName, 
											 restricted = RestrictedService, 
											 owner = Owner}, 
						  Req, 
						  Client, 
						  User = #user{admin = Admin}, 
						  AccessToken, 
						  Scope, 
						  AuthorizationMode) ->
	io:format("do_check_grant_permission1\n"),
	try
		case Client of
			public -> 
				io:format("do_check_grant_permission2\n"),
				ClientName = "public",
				AuthorizationOwner = [];
			_ ->
				io:format("do_check_grant_permission3\n"), 
				ClientName = binary_to_list(Client#client.name),
				AuthorizationOwner = Client#client.authorization_owner
		end,
		io:format("do_check_grant_permission4\n"),
		OwnerStr = binary_to_list(Owner),
		io:format("do_check_grant_permission5\n"),
		% Para consumir o serviço deve obedecer as regras
		% ===================================================================
		% O usuário é administrador e pode consumir qualquer serviço
		% Não é administrador e possui permissão em serviços não restritos a administradores e o cliente tem permissão para consumir os ws do owner
		PermiteAcessarComoAdmin = Admin,
		io:format("do_check_grant_permission6\n"),
		case AuthorizationOwner =:= <<>> orelse AuthorizationOwner == undefined of
			true -> 
				io:format("do_check_grant_permission7\n"),
				AuthorizationOwnerStr = "",
				PermiteAcessarWebserviceDoOwner = true;
			false ->
				io:format("do_check_grant_permission8\n"),
				case PermiteAcessarComoAdmin of
					false -> 
						io:format("do_check_grant_permission9\n"),
						PermiteAcessarServicoNaoRestritoComoUserNormal = not RestrictedService andalso ems_user_permission:has_grant_permission(Service, Req, User),
						case PermiteAcessarServicoNaoRestritoComoUserNormal of
							true ->
								io:format("do_check_grant_permission9.1\n"),
								PermiteAcessarWebserviceDoOwner = AuthorizationOwner == [] orelse lists:member(Owner, AuthorizationOwner);
							false ->
								io:format("do_check_grant_permission9.2\n"),
								PermiteAcessarWebserviceDoOwner = false
						end;
					true -> 
						io:format("do_check_grant_permission9.2\n"),
						PermiteAcessarWebserviceDoOwner = true
				end,
				io:format("do_check_grant_permission10\n"),
				AuthorizationOwnerStr = string:join(ems_util:binlist_to_list(AuthorizationOwner), ",")
		end,
		io:format("do_check_grant_permission11\n"),
		case PermiteAcessarWebserviceDoOwner of 
			false -> PermiteAcessarWsOAuth2 = ServiceName =:= <<"/authorize">> orelse ServiceName =:= <<"/code_request">> orelse ServiceName =:= <<"/resource">>;   
			true -> PermiteAcessarWsOAuth2 = true
		end,
		io:format("do_check_grant_permission12\n"),
		case PermiteAcessarComoAdmin orelse PermiteAcessarWebserviceDoOwner orelse PermiteAcessarWsOAuth2 of
			true -> 
				io:format("do_check_grant_permission13.true\n"),
				case AuthorizationMode of
					basic -> ems_db:inc_counter(ems_auth_user_basic_success);
					oauth2 -> ems_db:inc_counter(ems_auth_user_oauth2_success);
					_ -> ems_db:inc_counter(ems_auth_user_public_success)
				end,
				case not RestrictedService of
					true ->
						case PermiteAcessarComoAdmin of
							true -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for\033[0;32m service\033[0m: \033[01;34m~s\033[0m, \033[0;32madmin user login\033[0m: \033[01;34m~s\033[0m, \033[0;32mis_admin\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mowner\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization_owner\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr]);
							false -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for\033[0;32m service\033[0m: \033[01;34m~s\033[0m, \033[0;32muser login\033[0m: \033[01;34m~s\033[0m, \033[0;32mis_admin\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mowner\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization_owner\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr])
						end;
					false ->
						case PermiteAcessarComoAdmin of
							true -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for\033[0;32m restricted service\033[0m: \033[01;34m~s\033[0m, \033[0;32madmin user login\033[0m: \033[01;34m~s\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mowner\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization_owner\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), ClientName, OwnerStr, AuthorizationOwnerStr]);
							false -> ems_logger:info("ems_auth_user do_check_grant_permission success grant for\033[0;32m restricted service\033[0m: \033[01;34m~s\033[0m, \033[0;32muser login\033[0m: \033[01;34m~s\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mowner\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization_owner\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), ClientName, OwnerStr, AuthorizationOwnerStr])
						end
				end,
				io:format("do_check_grant_permission13.true.1\n"),
				{ok, Client, User, AccessToken, Scope};
			false -> 
				io:format("do_check_grant_permission13.false\n"),
				case AuthorizationMode of
					basic -> ems_db:inc_counter(ems_auth_user_basic_denied);
					oauth2 -> ems_db:inc_counter(ems_auth_user_oauth2_denied);
					_ -> ems_db:inc_counter(ems_auth_user_public_denied)
				end,
				case not RestrictedService of
					true -> ems_logger:error("ems_auth_user do_check_grant_permission denied grant for\033[0;32mservice\033[0m: \033[01;34m~s\033[0m, \033[0;32muser login\033[0m: \033[01;34m~s\033[0m, \033[0;32mis_admin\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mowner\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization_owner\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr]);
					false -> ems_logger:error("ems_auth_user do_check_grant_permission denied grant for\033[0;32m restricted service\033[0m: \033[01;34m~s\033[0m, \033[0;32muser login\033[0m: \033[01;34m~s\033[0m, \033[0;32mis_admin\033[0m: \033[01;34m~p\033[0m, \033[0;32mclient\033[0m: \033[01;34m~s\033[0m, \033[0;32mowner\033[0m: \033[01;34m~s\033[0m, \033[0;32mauthorization_owner\033[0m: \033[01;34m~p\033[0m.", [binary_to_list(Service#service.url), binary_to_list(User#user.login), Admin, ClientName, OwnerStr, AuthorizationOwnerStr])
				end,
				io:format("do_check_grant_permission13.false.1\n"),
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
		


