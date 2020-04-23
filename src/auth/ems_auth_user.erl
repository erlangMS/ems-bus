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
	case Type of
		<<"OPTIONS">> -> 
			ems_db:inc_counter(ems_auth_user_public_success),
			{ok, public, public, <<>>, <<>>};
		"HEAD" -> 
			ems_db:inc_counter(ems_auth_user_public_success),
			{ok, public, public, <<>>, <<>>};
		_ -> 
			case AuthorizationMode of
				basic -> 
					do_basic_authorization(Service, Request);
				oauth2 -> 
					do_bearer_authorization(Service, Request);
				_ -> 
					case AuthorizationPublicCheckCredential of
						true ->
							case do_basic_authorization(Service, Request) of
								{ok, Client, User, AccessToken, Scope} -> 
									{ok, Client, User, AccessToken, Scope};
								_ -> 
									{ok, public, public, <<>>, <<>>}
							end;
						false -> 
							ems_db:inc_counter(ems_auth_user_public_success),
							{ok, public, public, <<>>, <<>>}
					end
			end
	end.



%%====================================================================
%% Internal functions
%%====================================================================

-spec do_basic_authorization(#service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied, atom()}.
do_basic_authorization(Service, Request = #request{authorization = <<>>}) -> 
	do_bearer_authorization(Service, Request);
do_basic_authorization(Service = #service{auth_allow_user_inative_credentials = AuthAllowUserInativeCredentials}, Request = #request{authorization = Authorization}) ->
	case ems_util:parse_basic_authorization_header(Authorization) of
		{ok, Login, Password} ->
			?DEBUG("ems_auth_user do_basic_authorization Authorization: ~p.", [Authorization]),
			case ems_user:find_by_login_and_password(Login, Password) of
				{ok, User = #user{active = Active, ctrl_source_type = Table}} -> 
					case Active orelse AuthAllowUserInativeCredentials of
						true -> do_check_grant_permission(Service, Request, public, User, <<>>, atom_to_binary(Table, utf8), basic);
						false -> {error, access_denied, einative_user}
					end;
				Error -> Error
			end;
		{error, access_denied, ebasic_authorization_header_required} -> do_bearer_authorization(Service, Request); % Se o header não é Basic, então tenta oauth2
		Error -> Error
	end.


-spec do_bearer_authorization(#service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied, atom()}.
do_bearer_authorization(Service, Request = #request{authorization = <<>>}) ->
	AccessToken = ems_util:get_querystring(<<"token">>, <<"access_token">>, <<>>, Request),
	do_oauth2_check_access_token(AccessToken, Service, Request);
do_bearer_authorization(Service, Request = #request{authorization = Authorization}) ->	
	?DEBUG("ems_auth_user do_bearer_authorization Authorization: ~p.", [Authorization]),
	case ems_util:parse_bearer_authorization_header(Authorization) of
		{ok, AccessToken} -> 
			do_oauth2_check_access_token(AccessToken, Service, Request);
		Error -> 
			ems_db:inc_counter(ems_auth_user_oauth2_denied),
			Error
	end.

-spec do_oauth2_check_access_token(binary(), #service{}, #request{}) -> {ok, #client{} | public, #user{} | public, binary(), binary()} | {error, access_denied}.
do_oauth2_check_access_token(<<>>, _, _) -> 
	ems_db:inc_counter(ems_auth_user_oauth2_denied),
	{error, access_denied, eaccess_token_required};
do_oauth2_check_access_token(AccessToken, Service, Req) ->
	case byte_size(AccessToken) > 32 of
		true -> 
			ems_db:inc_counter(ems_auth_user_oauth2_denied),
			{error, access_denied, einvalid_access_token_size};
		false -> 
			case oauth2:verify_access_token(AccessToken, undefined) of
				{ok, {[], [{<<"client">>, Client}, 
						   {<<"resource_owner">>, User}, 
						   {<<"expiry_time">>, _ExpityTime}, 
						   {<<"scope">>, Scope}]}} -> 
					do_check_grant_permission(Service, Req, Client, User, AccessToken, Scope, oauth2);
				_ -> 
					ems_db:inc_counter(ems_auth_user_oauth2_denied),
					{error, access_denied, einvalid_access_token}
			end
	end.
	

-spec do_check_grant_permission(#service{}, #request{}, #client{} | public, #user{}, binary(), binary(), atom()) -> {ok, #client{}, #user{}, binary(), binary()} | {error, access_denied}.
do_check_grant_permission(Service = #service{restricted = RestrictedService}, 
						  Req, 
						  Client, 
						  User = #user{admin = Admin}, 
						  AccessToken, 
						  Scope, 
						  AuthorizationMode) ->
	% Para consumir o serviço deve obedecer as regras
	% ===================================================================
	% O usuário é administrador e pode consumir qualquer serviço
	% Não é administrador e possui permissão em serviços não restritos a administradores
	case Admin orelse not RestrictedService orelse ems_user_permission:has_grant_permission(Service, Req, User) of
		true -> 
			case AuthorizationMode of
				basic -> ems_db:inc_counter(ems_auth_user_basic_success);
				oauth2 -> ems_db:inc_counter(ems_auth_user_oauth2_success);
				_ -> ems_db:inc_counter(ems_auth_user_public_success)
			end,
			{ok, Client, User, AccessToken, Scope};
		false -> 
			case AuthorizationMode of
				basic -> ems_db:inc_counter(ems_auth_user_basic_denied);
				oauth2 -> ems_db:inc_counter(ems_auth_user_oauth2_denied);
				_ -> ems_db:inc_counter(ems_auth_user_public_denied)
			end,
			case RestrictedService of
				true ->	{error, access_denied, erestricted_service};
				false -> {error, access_denied, eno_grant_permission}
			end
	end.

