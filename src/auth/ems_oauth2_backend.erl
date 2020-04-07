%%********************************************************************
%% @title ems_oauth2_backend
%% @version 1.0.0
%% @doc Backend of OAuth2 subsystem
%% @author Alyssom Ribeiro <alyssonribeiro@unb.br>
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_oauth2_backend).

%-behavior(oauth2_backend).
-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%%% API
-export([start/0, start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).


-export([authenticate_user/2]).
-export([authenticate_client/2]).
-export([authorize_refresh_token/3]).
-export([get_client_identity/2]).
-export([associate_access_code/3]).
-export([associate_refresh_token/3]).
-export([associate_access_token/3]).
-export([resolve_access_code/2]).
-export([resolve_refresh_token/2]).
-export([resolve_access_token/2]).
-export([revoke_access_code/2]).
-export([revoke_access_token/2]).
-export([revoke_refresh_token/2]).
-export([get_redirection_uri/2]).
-export([verify_redirection_uri/3]).
-export([verify_client_scope/3]).
-export([verify_resowner_scope/3]).
-export([verify_scope/3]).
        
-record(a, { client   = undefined    :: undefined | term()
           , resowner = undefined    :: undefined | term()
           , scope                   :: oauth2:scope()
           , ttl      = 0            :: non_neg_integer()
           }).

-record(state, {}). 

-define(SERVER, ?MODULE).

%%%===================================================================
%%% Teste
%%%===================================================================

start() -> 
	ok.

start(Service) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Service, []).

stop() -> ok.
  


%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(_Service = #service{properties = Props}) ->
    Conf = ems_config:getConfig(),
    
    application:set_env(oauth2, backend, ems_oauth2_backend),
	application:set_env(oauth2, expiry_time, Conf#config.oauth2_refresh_token),

	PersistTokenSGBDEnabled = ems_util:parse_bool(maps:get(<<"persist_token_sgbd_enabled">>, Props, false)),
	ems_db:set_param(persist_token_sgbd_enabled, PersistTokenSGBDEnabled),

	DatasourcePersistSGBD = maps:get(<<"datasource_persist_token_sgbd">>, Props, <<>>),
	ems_db:set_param(datasource_persist_token_sgbd, DatasourcePersistSGBD),

	SqlPersistAccessCode = ems_util:str_trim(binary_to_list(maps:get(<<"sql_persist_access_code">>, Props, <<>>))),
	SqlSelectAccessCode = ems_util:str_trim(binary_to_list(maps:get(<<"sql_select_access_code">>, Props, <<>>))),
	ems_db:set_param(sql_persist_access_code, SqlPersistAccessCode),
	ems_db:set_param(sql_select_access_code, SqlSelectAccessCode),

	SqlPersistRefreshToken = ems_util:str_trim(binary_to_list(maps:get(<<"sql_persist_refresh_token">>, Props, <<>>))),
	SqlSelectRefreshToken = ems_util:str_trim(binary_to_list(maps:get(<<"sql_select_refresh_token">>, Props, <<>>))),
	ems_db:set_param(sql_persist_refresh_token, SqlPersistRefreshToken),
	ems_db:set_param(sql_select_refresh_token, SqlSelectRefreshToken),

	SqlPersistAccessToken = ems_util:str_trim(binary_to_list(maps:get(<<"sql_persist_access_token">>, Props, <<>>))),
	SqlSelectAccessToken = ems_util:str_trim(binary_to_list(maps:get(<<"sql_select_access_token">>, Props, <<>>))),
	ems_db:set_param(sql_persist_access_token, SqlPersistAccessToken),
	ems_db:set_param(sql_select_access_token, SqlSelectAccessToken),
	
	PassportCodeEnabled = ems_util:parse_bool(maps:get(<<"passport_code_enabled">>, Props, false)),
	DatasourcePassportCode = maps:get(<<"datasource_passport_code">>, Props, <<>>),
	SqlSelectPassportCode = ems_util:str_trim(binary_to_list(maps:get(<<"sql_select_passport_code">>, Props, <<>>))),
	SqlDisablePassportCode = ems_util:str_trim(binary_to_list(maps:get(<<"sql_disable_passport_code">>, Props, <<>>))),
	ems_db:set_param(passport_code_enabled, PassportCodeEnabled),
	ems_db:set_param(datasource_passport_code, DatasourcePassportCode),
	ems_db:set_param(sql_select_passport_code, SqlSelectPassportCode),
	ems_db:set_param(sql_disable_passport_code, SqlDisablePassportCode),

	NewState = #state{},
    {ok, NewState}. 
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.
    
handle_call(_Msg, _From, State) ->
	{reply, _Msg, State}.

handle_info({expire, Table, Key}, State) ->
	ems_db:delete(Table, Key),
	{noreply, State};

handle_info(_Msg, State) ->
   {noreply, State}.

handle_info(State) ->
   {noreply, State}.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    


%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

authenticate_user(undefined, _) -> unauthorized_user;
authenticate_user(User, _) ->
	{ok, {<<>>, User}}.
	

authenticate_client(undefined, _) ->
	{error, unauthorized_client};
authenticate_client(Client, _) ->
	{ok, {[], Client}}.


get_client_identity(undefined, _) ->
	{error, unauthorized_client};
get_client_identity(Client, _) ->
	{ok, {[], Client}}.
        

associate_access_code(AccessCode, Context, _AppContext) ->
	try
		AuthOAuth2AccessCode = #auth_oauth2_access_code{id = AccessCode, context = Context},
		mnesia:dirty_write(auth_oauth2_access_code_table, AuthOAuth2AccessCode),
		associate_access_code_sgbd(AuthOAuth2AccessCode),
		{ok, Context}
	catch
		_:ReasonException -> 
			ems_logger:error("associate_access_code failed. Reason: ~p.", [ReasonException]),
			{error, eparse_associate_access_code}
	end.
    

associate_access_code_sgbd(#auth_oauth2_access_code{id = AccessCode, context = Context}) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				SqlPersist = ems_db:get_param(sql_persist_access_code),
				case SqlPersist =/= "" of
					true ->
						{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
						case ems_odbc_pool:get_connection(Ds) of
							{ok, Ds2} ->
								Context1 = term_to_binary(Context),
								Context2 = base64:encode(Context1),
								ParamsSql = [{{sql_varchar, 32}, [binary_to_list(AccessCode)]},
											{{sql_varchar, 4000}, [binary_to_list(Context2)]}
											],
								ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
								ems_odbc_pool:release_connection(Ds2);
							{error, Reason} ->
								ems_logger:error("ems_oauth2_backend associate_access_code_sgbd failed to get database connection. Reason: ~p.", [Reason])
						end;
					false -> ok
				end;
			false -> ok
		end
	catch
		_:ReasonException -> 
			ems_logger:error("associate_access_code_sgbd failed. Reason: ~p.", [ReasonException]),
			{error, eparse_associate_access_code_sgbd}
	end.


associate_refresh_token(RefreshToken, Context, _) ->
	try
		AuthOauth2RefreshToken = #auth_oauth2_refresh_token{id = RefreshToken, context = Context},
		mnesia:dirty_write(auth_oauth2_refresh_token_table, AuthOauth2RefreshToken),
		associate_refresh_token_sgbd(AuthOauth2RefreshToken),
		{ok, Context}
	catch
		_:ReasonException -> 
			ems_logger:error("associate_refresh_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_associate_refresh_token}
	end.
		

associate_refresh_token_sgbd(#auth_oauth2_refresh_token{id = RefreshToken, context = Context}) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				SqlPersist = ems_db:get_param(sql_persist_refresh_token),
				case SqlPersist =/= "" of
					true ->
						{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
						case ems_odbc_pool:get_connection(Ds) of
							{ok, Ds2} ->
								Context1 = term_to_binary(Context),
								Context2 = base64:encode(Context1),
								ParamsSql = [{{sql_varchar, 32}, [binary_to_list(RefreshToken)]},
											{{sql_varchar, 4000}, [binary_to_list(Context2)]}
											],
								ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
								ems_odbc_pool:release_connection(Ds2);
							{error, Reason} ->
								ems_logger:error("ems_oauth2_backend associate_refresh_token_sgbd failed to get database connection. Reason: ~p.", [Reason])
						end,
						ok;
					false -> ok
				end;
			false -> ok
		end
	catch
		_:ReasonException -> 
			ems_logger:error("associate_refresh_token_sgbd failed. Reason: ~p.", [ReasonException]),
			{error, eparse_associate_refresh_token_sgbd}
	end.


associate_access_token(AccessToken, Context, _) ->
	try
		AuthOauth2AccessToken = #auth_oauth2_access_token{id = AccessToken, context = Context},
		mnesia:dirty_write(auth_oauth2_access_token_table, AuthOauth2AccessToken),
		associate_access_token_sgbd(AuthOauth2AccessToken),
		{ok, Context}
	catch
		_:ReasonException -> 
			ems_logger:error("associate_access_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_associate_access_token}
	end.
		

associate_access_token_sgbd(#auth_oauth2_access_token{id = AccessToken, context = Context}) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				SqlPersist = ems_db:get_param(sql_persist_access_token),
				case SqlPersist =/= "" of
					true ->
						{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
						case ems_odbc_pool:get_connection(Ds) of
							{ok, Ds2} ->
								Context1 = term_to_binary(Context),
								Context2 = base64:encode(Context1),
								ParamsSql = [{{sql_varchar, 32}, [binary_to_list(AccessToken)]},
											{{sql_varchar, 4000}, [binary_to_list(Context2)]}
											],
								ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
								ems_odbc_pool:release_connection(Ds2);
							{error, Reason} ->
								ems_logger:error("ems_oauth2_backend associate_access_token_sgbd failed to get database connection. Reason: ~p.", [Reason])
						end,
						ok;
					false -> ok
				end;
			false -> ok
		end
	catch
		_:ReasonException -> 
			ems_logger:error("associate_access_token_sgbd failed. Reason: ~p.", [ReasonException]),
			{error, eparse_associate_access_token_sgbd}
	end.



resolve_access_code(AccessCode, _) ->
	try
		case ems_db:get(auth_oauth2_access_code_table, AccessCode) of
			{ok, #auth_oauth2_access_code{context = Context}} -> 	
				{ok, {[], Context}};
			_ -> 
				case resolve_access_code_sgbd(AccessCode) of
					{ok, #auth_oauth2_access_code{context = Context2}} -> 	
						{ok, {[], Context2}};
					Error -> 
						Error
				end
		end
	catch
		_:ReasonException -> 
			ems_logger:error("resolve_access_code failed. Reason: ~p.", [ReasonException]),
			{error, eparse_resolve_access_code}
	end.
		

resolve_access_code_sgbd(AccessCode) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				SqlSelect = ems_db:get_param(sql_select_access_code),
				case SqlSelect =/= "" of
					true ->
						{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
						case ems_odbc_pool:get_connection(Ds) of
							{ok, Ds2} ->
								ParamsSql = [{{sql_varchar, 60}, [binary_to_list(AccessCode)]}],
								case ems_odbc_pool:param_query(Ds2, SqlSelect, ParamsSql) of
									{selected,_Fields, [{_AccessCode, _DtRegistro, Context}]} ->
										Context1 = base64:decode(list_to_binary(Context)),
										Context2 = binary_to_term(Context1),
										ems_logger:debug("ems_oauth2_backend resolve_access_code_sgbd success to access_code ~p.", [AccessCode]),
										AuthOAuth2AccessCode = #auth_oauth2_access_code{id = AccessCode, context = Context2},
										mnesia:dirty_write(auth_oauth2_access_code_table, AuthOAuth2AccessCode),
										Result = {ok, AuthOAuth2AccessCode};
									_ ->
										Result = {error, invalid_code} 
								end,
								ems_odbc_pool:release_connection(Ds2),
								Result;
							{error, Reason} ->
								ems_logger:error("ems_oauth2_backend resolve_access_code_sgbd failed to get database connection. Reason: ~p.", [Reason]),
								{error, invalid_code} 
						end;
					false -> 
						{error, invalid_code} 
				end;
			false -> 
				{error, invalid_code} 
		end
	catch
		_:ReasonException -> 
			ems_logger:error("resolve_access_code_sgbd failed. Reason: ~p.", [ReasonException]),
			{error, eparse_resolve_access_code_sgbd}
	end.
	
		


resolve_refresh_token(RefreshToken, _AppContext) ->
	try
		case ems_db:get(auth_oauth2_refresh_token_table, RefreshToken) of
		   {ok, #auth_oauth2_refresh_token{context = Context}} -> 	
				{ok, {[], Context}};
			_ -> 
				case resolve_refresh_token_sgbd(RefreshToken) of
				   {ok, #auth_oauth2_refresh_token{context = Context2}} -> 	
						{ok, {[], Context2}};
					Error -> 
						Error
				end
		end
	catch
		_:ReasonException -> 
			ems_logger:error("resolve_refresh_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_resolve_refresh_token}
	end.
		

resolve_refresh_token_sgbd(RefreshToken) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				SqlSelect = ems_db:get_param(sql_select_refresh_token),
				case SqlSelect =/= "" of
					true ->
						{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
						case ems_odbc_pool:get_connection(Ds) of
							{ok, Ds2} ->
								ParamsSql = [{{sql_varchar, 60}, [binary_to_list(RefreshToken)]}],
								case ems_odbc_pool:param_query(Ds2, SqlSelect, ParamsSql) of
									{selected,_Fields, [{_AccessCode, _DtRegistro, Context}]} ->
										Context1 = base64:decode(list_to_binary(Context)),
										Context2 = binary_to_term(Context1),
										ems_logger:debug("ems_oauth2_backend resolve_refresh_token_sgbd success to refresh_token ~p.", [RefreshToken]),
										AuthOauth2RefreshToken = #auth_oauth2_refresh_token{id = RefreshToken, context = Context2},
										mnesia:dirty_write(auth_oauth2_refresh_token_table, AuthOauth2RefreshToken),
										Result = {ok, AuthOauth2RefreshToken};
									_ ->
										Result = {error, invalid_code} 
								end,
								ems_odbc_pool:release_connection(Ds2),
								Result;
							{error, Reason} ->
								ems_logger:error("ems_oauth2_backend resolve_refresh_token_sgbd failed to get database connection. Reason: ~p.", [Reason]),
								{error, invalid_code} 
						end;
					false -> 
						{error, invalid_code} 
				end;
			false -> {error, invalid_code} 
		end
	catch
		_:ReasonException -> 
			ems_logger:error("resolve_refresh_token_sgbd failed. Reason: ~p.", [ReasonException]),
			{error, eparse_resolve_refresh_token_sgbd}
	end.
		



resolve_access_token(AccessToken, _) ->
	try
		case ems_db:get(auth_oauth2_access_token_table, AccessToken) of
		   {ok, #auth_oauth2_access_token{context = Context}} -> 	
				{ok, {[], Context}};
			_ -> 
				case resolve_access_token_sgbd(AccessToken) of
				   {ok, #auth_oauth2_access_token{context = Context2}} -> 	
							{ok, {[], Context2}};
					Error -> 
						Error
				end
		end
	catch
		_:ReasonException -> 
			ems_logger:error("resolve_access_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_resolve_access_token}
	end.
		

resolve_access_token_sgbd(AccessToken) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				SqlSelect = ems_db:get_param(sql_select_access_token),
				case SqlSelect =/= "" of
					true ->
						{ok, Ds} = ems_db:find_by_id(service_datasource, 1),
						case ems_odbc_pool:get_connection(Ds) of
							{ok, Ds2} ->
								ParamsSql = [{{sql_varchar, 60}, [binary_to_list(AccessToken)]}],
								case ems_odbc_pool:param_query(Ds2, SqlSelect, ParamsSql) of
									{selected,_Fields, [{_AccessCode, _DtRegistro, Context}]} ->
										Context1 = base64:decode(list_to_binary(Context)),
										Context2 = binary_to_term(Context1),
										ems_logger:debug("ems_oauth2_backend resolve_access_token_sgbd success to access_token ~p.", [AccessToken]),
										AuthOauth2AccessToken = #auth_oauth2_access_token{id = AccessToken, context = Context2},
										mnesia:dirty_write(auth_oauth2_access_token_table, AuthOauth2AccessToken),
										Result = {ok, AuthOauth2AccessToken};
									_ ->
										ems_logger:debug("ems_oauth2_backend resolve_access_token_sgbd failed to access_token ~p.", [AccessToken]),
										Result = {error, invalid_code} 
								end,
								ems_odbc_pool:release_connection(Ds2),
								Result;
							{error, Reason} ->
								ems_logger:error("ems_oauth2_backend resolve_access_token_sgbd failed to get database connection. Reason: ~p.", [Reason]),
								{error, invalid_code} 
						end;
					false -> 
						ems_logger:debug("ems_oauth2_backend resolve_access_token_sgbd failed. SqlSelect == "". Reason:_token ~p.", [AccessToken]),
						{error, invalid_code} 
				end;
			false -> 
				ems_logger:debug("ems_oauth2_backend resolve_access_token_sgbd exception. Reason:_token ~p.", [AccessToken]),
				{error, invalid_code} 
		end
	catch
		_:ReasonException -> 
			ems_logger:error("resolve_access_token_sgbd failed. Reason: ~p.", [ReasonException]),
			{error, eparse_resolve_access_token_sgbd}
	end.
		



revoke_access_code(AccessCode, _AppContext) ->
	try
		case ems_db:get(auth_oauth2_access_code_table, AccessCode) of
			{ok, Record} -> 
				ems_db:delete(Record);
			_ -> ok
		end,
		{ok, []}
	catch
		_:ReasonException -> 
			ems_logger:error("revoke_access_code failed. Reason: ~p.", [ReasonException]),
			{error, eparse_revoke_access_code}
	end.


revoke_access_token(AccessToken, _) ->
	try
		case ems_db:get(auth_oauth2_access_token_table, AccessToken) of
			{ok, Record} -> 
				ems_db:delete(Record);
			_ -> ok
		end,
		{ok, []}
	catch
		_:ReasonException -> 
			ems_logger:error("revoke_access_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_revoke_access_token}
	end.
		

revoke_refresh_token(RefreshToken, _) ->
	try
		case ems_db:get(auth_oauth2_refresh_token_table, RefreshToken) of
			{ok, Record} -> 
				ems_db:delete(Record);
			_ -> ok
		end,
		{ok, []}
	catch
		_:ReasonException -> 
			ems_logger:error("revoke_refresh_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_revoke_refresh_token}
	end.
		

get_redirection_uri(Client, _) ->
    case get_client_identity(Client, [])  of
        {ok, #client{redirect_uri = RedirectUri}} -> {ok, RedirectUri};
        _ -> {error, einvalid_uri} 
    end.


verify_redirection_uri(#client{redirect_uri = RedirUri}, ClientUri, _) ->
    case ClientUri =:= RedirUri of
		true -> 
			{ok, []};
		_Error -> 
			{error, unauthorized_client}
    end.

verify_client_scope(#client{id = ClientID}, Scope, _) ->
	case ems_client:find_by_id(ClientID) of
        {ok, #client{scope = Scope0}} ->     
			case Scope =:= Scope0 of
				true -> 
					{ok, {[], Scope0}};
				_ -> {error, unauthorized_client}
			end;
        _ -> {error, invalid_scope}
    end.
    
verify_resowner_scope(_ResOwner, Scope, _) ->
    {ok, {[], Scope}}.

verify_scope(_RegScope, Scope , _) ->
    {ok, {[], Scope}}.

    
% função criada pois a biblioteca OAuth2 não trata refresh_tokens
authorize_refresh_token(Client, RefreshToken, Scope) ->
	try
		case resolve_refresh_token(RefreshToken, []) of
			{ok, {_, [_, {_, ResourceOwner}, _, _]}} -> 
				case verify_client_scope(Client, Scope, []) of
					{error, _} -> {error, invalid_scope};
					{ok, {Ctx3, _}} ->
						Result = {ok, {Ctx3, #a{client = Client,
									   resowner = ResourceOwner,
									   scope = Scope,
									   ttl = oauth2_config:expiry_time(password_credentials)
						}}},
						Result
				end;
			Error -> Error
		end
	catch
		_:ReasonException -> 
			ems_logger:error("authorize_refresh_token failed. Reason: ~p.", [ReasonException]),
			{error, eparse_authorize_refresh_token}
	end.
		


