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
-export([authorize_refresh_token/4]).
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
        
-record(a, { client   = undefined    :: undefined | term()
           , resowner = undefined    :: undefined | term()
           , scope                   :: oauth2:scope()
           , state                   :: oauth2:scope()
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

	PersistTokenSGBDEnabled = ems_util:parse_bool(maps:get(<<"persist_token_sgbd_enabled">>, Props, ?PERSIST_TOKEN_SGBD_ENABLED)),
	ems_logger:info("ems_oauth2_backend init persist_token_sgbd_enabled: ~p", [PersistTokenSGBDEnabled]),
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

	% Inicializa cache de tokens ETS
	ems_auth_token_cache:start(),
	
	% Inicializa cache de permissões ETS
	ems_permission_cache:start(),
	
	% Agenda limpeza periódica dos caches (a cada 60 segundos)
	erlang:send_after(60000, self(), cleanup_token_cache),
	erlang:send_after(60000, self(), cleanup_permission_cache),

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

handle_info(cleanup_token_cache, State) ->
	ems_auth_token_cache:cleanup_expired(),
	erlang:send_after(60000, self(), cleanup_token_cache),
	{noreply, State};

handle_info(cleanup_permission_cache, State) ->
	ems_permission_cache:cleanup_expired(),
	erlang:send_after(60000, self(), cleanup_permission_cache),
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
			ems_logger:error("ems_oauth2_backend associate_access_code exception. AccessCode: ~p. Reason: ~p.", [AccessCode, ReasonException]),
			{error, eparse_associate_access_code}
	end.
    

associate_access_code_sgbd(#auth_oauth2_access_code{id = AccessCode, context = Context}) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				T1 = ems_util:get_timestamp(),
				SqlPersist = ems_db:get_param(sql_persist_access_code),
				case SqlPersist =/= "" of
					true ->
						case ems_db:find_by_id(service_datasource, 1) of
							{ok, Ds} -> 
								case ems_odbc_pool:get_connection(Ds) of
									{ok, Ds2} ->
										Context1 = term_to_binary(sanitize_context_for_save(Context)),
                                        ems_logger:info("DEBUG: Sanitized Context. Original Client Size: ~p. Sanitized: ~p", [tuple_size(proplists:get_value(<<"client">>, Context)), tuple_size(proplists:get_value(<<"client">>, sanitize_context_for_save(Context)))]),
										Context2 = base64:encode(Context1),
										ParamsSql = [{{sql_varchar, 32}, [binary_to_list(AccessCode)]},
													{{sql_varchar, 4000}, [binary_to_list(Context2)]}
													],
										ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
										ems_odbc_pool:release_connection(Ds2);
									{error, Reason} ->
										ems_logger:error("ems_oauth2_backend associate_access_code_sgbd failed to get database connection. Reason: ~p.", [Reason]),
										ok
								end;
							_ -> 
								ems_logger:error("ems_oauth2_backend associate_access_code_sgbd failed. Datasource service_datasource not found."),
								ok
						end;
					false -> ok
				end,
				T2 = ems_util:get_timestamp(),
				ems_logger:info("ems_oauth2_backend associate_access_code_sgbd execution time: ~p ms.", [T2 - T1]);
			false -> ok
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend associate_access_code_sgbd exception. AccessCode: ~p. Reason: ~p.", [AccessCode, ReasonException]),
			ok   % não pode retornar erro porque senão a pesquisa em user_fs não funciona
	end.


associate_refresh_token(RefreshToken, Context, _) ->
	try
		AuthOauth2RefreshToken = #auth_oauth2_refresh_token{id = RefreshToken, context = Context},
		mnesia:dirty_write(auth_oauth2_refresh_token_table, AuthOauth2RefreshToken),
		associate_refresh_token_sgbd(AuthOauth2RefreshToken),
		{ok, Context}
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend associate_refresh_token exception. RefreshToken: ~p. Reason: ~p.", [RefreshToken, ReasonException]),
			{error, eassociate_refresh_token}
	end.
		

associate_refresh_token_sgbd(#auth_oauth2_refresh_token{id = RefreshToken, context = Context}) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				T1 = ems_util:get_timestamp(),
				SqlPersist = ems_db:get_param(sql_persist_refresh_token),
				case SqlPersist =/= "" of
					true ->
						case ems_db:find_by_id(service_datasource, 1) of
							{ok, Ds} -> 
								case ems_odbc_pool:get_connection(Ds) of
									{ok, Ds2} ->
										Context1 = term_to_binary(sanitize_context_for_save(Context)),
										Context2 = base64:encode(Context1),
										ParamsSql = [{{sql_varchar, 32}, [binary_to_list(RefreshToken)]},
													{{sql_varchar, 4000}, [binary_to_list(Context2)]}
													],
										ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
										ems_odbc_pool:release_connection(Ds2);
									{error, Reason} ->
										ems_logger:error("ems_oauth2_backend associate_refresh_token_sgbd failed to get database connection. Reason: ~p.", [Reason]),
										ok
								end;
							_ -> 
								ems_logger:error("ems_oauth2_backend associate_refresh_token_sgbd failed. Datasource service_datasource not found."),
								ok
						end,
						ok;
					false -> ok
				end,
				T2 = ems_util:get_timestamp(),
				ems_logger:info("ems_oauth2_backend associate_refresh_token_sgbd execution time: ~p ms.", [T2 - T1]);
			false -> ok
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend associate_refresh_token_sgbd failed. RefreshToken: ~p. Reason: ~p.", [RefreshToken, ReasonException]),
			ok  % não pode retornar erro porque senão a pesquisa em user_fs não funciona
	end.


associate_access_token(AccessToken, Context, _) ->
	try
		AuthOauth2AccessToken = #auth_oauth2_access_token{id = AccessToken, context = Context},
		mnesia:dirty_write(auth_oauth2_access_token_table, AuthOauth2AccessToken),
		associate_access_token_sgbd(AuthOauth2AccessToken),
		{ok, Context}
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend associate_access_token failed. AccessToken: ~p. Reason: ~p.", [AccessToken, ReasonException]),
			{error, eparse_associate_access_token}
	end.
		

associate_access_token_sgbd(#auth_oauth2_access_token{id = AccessToken, context = Context}) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				T1 = ems_util:get_timestamp(),
				SqlPersist = ems_db:get_param(sql_persist_access_token),
				case SqlPersist =/= "" of
					true ->
						case ems_db:find_by_id(service_datasource, 1) of
							{ok, Ds} -> 
								case ems_odbc_pool:get_connection(Ds) of
									{ok, Ds2} ->
										Context1 = term_to_binary(sanitize_context_for_save(Context)),
										Context2 = base64:encode(Context1),
										ParamsSql = [{{sql_varchar, 32}, [binary_to_list(AccessToken)]},
													{{sql_varchar, 4000}, [binary_to_list(Context2)]}
													],
										ems_odbc_pool:param_query(Ds2, SqlPersist, ParamsSql),
										ems_odbc_pool:release_connection(Ds2);
									{error, Reason} ->
										ems_logger:error("ems_oauth2_backend associate_access_token_sgbd failed to get database connection. Reason: ~p.", [Reason]),
										ok
								end,
								ok;
							_ -> 
								ems_logger:error("ems_oauth2_backend associate_access_token_sgbd failed. Datasource service_datasource not found."),
								ok
						end;
					false -> ok
				end,
				T2 = ems_util:get_timestamp(),
				ems_logger:info("ems_oauth2_backend associate_access_token_sgbd execution time: ~p ms.", [T2 - T1]);
			false -> ok
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend associate_access_token_sgbd failed. AccessToken: ~p. Reason: ~p.", [AccessToken, ReasonException]),
			ok  % não pode retornar erro porque senão a pesquisa em user_fs não funciona
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
			ems_logger:error("ems_oauth2_backend resolve_access_code failed. AccessCode: ~p Reason: ~p.", [AccessCode, ReasonException]),
			{error, eparse_resolve_access_code}
	end.
		

resolve_access_code_sgbd(AccessCode) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				T1 = ems_util:get_timestamp(),
				SqlSelect = ems_db:get_param(sql_select_access_code),
				Result = case SqlSelect =/= "" of
					true ->
						case ems_db:find_by_id(service_datasource, 1) of
							{ok, Ds} -> 
								case ems_odbc_pool:get_connection(Ds) of
									{ok, Ds2} ->
										ParamsSql = [{{sql_varchar, 60}, [binary_to_list(AccessCode)]}],
										Res = case ems_odbc_pool:param_query(Ds2, SqlSelect, ParamsSql) of
											{selected,_Fields, [{_AccessCode, _DtRegistro, Context}]} ->
												Context1 = base64:decode(list_to_binary(Context)),
												Context2 = binary_to_term(Context1, [safe]),
												Context3 = sanitize_context_for_load(Context2),
												ems_logger:debug("ems_oauth2_backend resolve_access_code_sgbd success to access_code ~p.", [AccessCode]),
												AuthOAuth2AccessCode = #auth_oauth2_access_code{id = AccessCode, context = Context3},
												mnesia:dirty_write(auth_oauth2_access_code_table, AuthOAuth2AccessCode),
												{ok, AuthOAuth2AccessCode};
											_ ->
												{error, invalid_code} 
										end,
										ems_odbc_pool:release_connection(Ds2),
										Res;
									{error, Reason} ->
										ems_logger:error("ems_oauth2_backend resolve_access_code_sgbd failed to get database connection. Reason: ~p.", [Reason]),
										{error, invalid_code} 
								end;
							_ -> 
								ems_logger:error("ems_oauth2_backend resolve_access_code_sgbd failed. Datasource service_datasource not found."),
								{error, invalid_code} 
						end;
					false -> 
						{error, invalid_code} 
				end,
				T2 = ems_util:get_timestamp(),
				ems_logger:info("ems_oauth2_backend resolve_access_code_sgbd execution time: ~p ms.", [T2 - T1]),
				Result;
			false -> 
				{error, invalid_code} 
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend resolve_access_code_sgbd failed. AccessCode: ~p. Reason: ~p.", [AccessCode, ReasonException]),
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
			ems_logger:error("ems_oauth2_backend resolve_refresh_token failed. RefreshToken: ~p Reason: ~p.", [RefreshToken, ReasonException]),
			{error, eparse_resolve_refresh_token}
	end.
		

resolve_refresh_token_sgbd(RefreshToken) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				T1 = ems_util:get_timestamp(),
				SqlSelect = ems_db:get_param(sql_select_refresh_token),
				Result = case SqlSelect =/= "" of
					true ->
						case ems_db:find_by_id(service_datasource, 1) of
							{ok, Ds} -> 
								case ems_odbc_pool:get_connection(Ds) of
									{ok, Ds2} ->
										ParamsSql = [{{sql_varchar, 60}, [binary_to_list(RefreshToken)]}],
										Res = case ems_odbc_pool:param_query(Ds2, SqlSelect, ParamsSql) of
											{selected,_Fields, [{_AccessCode, _DtRegistro, Context}]} ->
												Context1 = base64:decode(list_to_binary(Context)),
												Context2 = binary_to_term(Context1, [safe]),
												Context3 = sanitize_context_for_load(Context2),
												ems_logger:debug("ems_oauth2_backend resolve_refresh_token_sgbd success to refresh_token ~p.", [RefreshToken]),
												AuthOauth2RefreshToken = #auth_oauth2_refresh_token{id = RefreshToken, context = Context3},
												mnesia:dirty_write(auth_oauth2_refresh_token_table, AuthOauth2RefreshToken),
												{ok, AuthOauth2RefreshToken};
											_ ->
												{error, invalid_code} 
										end,
										ems_odbc_pool:release_connection(Ds2),
										Res;
									{error, Reason} ->
										ems_logger:error("ems_oauth2_backend resolve_refresh_token_sgbd failed to get database connection. Reason: ~p.", [Reason]),
										{error, invalid_code} 
								end;
							_ -> 
								ems_logger:error("ems_oauth2_backend resolve_refresh_token_sgbd failed. Datasource service_datasource not found."),
								{error, invalid_code} 
						end;
					false -> 
						{error, invalid_code} 
				end,
				T2 = ems_util:get_timestamp(),
				ems_logger:info("ems_oauth2_backend resolve_refresh_token_sgbd execution time: ~p ms.", [T2 - T1]),
				Result;
			false -> {error, invalid_code} 
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend resolve_refresh_token_sgbd failed. RefreshToken: ~p. Reason: ~p.", [RefreshToken, ReasonException]),
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
			ems_logger:error("ems_oauth2_backend resolve_access_token failed. AccessToken: ~p Reason: ~p.", [AccessToken, ReasonException]),
			{error, eparse_resolve_access_token}
	end.
		

resolve_access_token_sgbd(AccessToken) ->
	try
		PersistTokenSGBDEnabled = ems_db:get_param(persist_token_sgbd_enabled),
		case PersistTokenSGBDEnabled of
			true ->
				T1 = ems_util:get_timestamp(),
				SqlSelect = ems_db:get_param(sql_select_access_token),
				Result = case SqlSelect =/= "" of
					true ->
						case ems_db:find_by_id(service_datasource, 1) of
							{ok, Ds} -> 
								case ems_odbc_pool:get_connection(Ds) of
									{ok, Ds2} ->
										ParamsSql = [{{sql_varchar, 60}, [binary_to_list(AccessToken)]}],
										Res = case ems_odbc_pool:param_query(Ds2, SqlSelect, ParamsSql) of
											{selected,_Fields, [{_AccessCode, _DtRegistro, Context}]} ->
												Context1 = base64:decode(list_to_binary(Context)),
												Context2 = binary_to_term(Context1, [safe]),
												Context3 = sanitize_context_for_load(Context2),
												ems_logger:debug("ems_oauth2_backend resolve_access_token_sgbd success to access_token ~p.", [AccessToken]),
												AuthOauth2AccessToken = #auth_oauth2_access_token{id = AccessToken, context = Context3},
												mnesia:dirty_write(auth_oauth2_access_token_table, AuthOauth2AccessToken),
												{ok, AuthOauth2AccessToken};
											_ ->
												ems_logger:debug("ems_oauth2_backend resolve_access_token_sgbd failed to access_token ~p.", [AccessToken]),
												{error, invalid_code} 
										end,
										ems_odbc_pool:release_connection(Ds2),
										Res;
									{error, Reason} ->
										ems_logger:error("ems_oauth2_backend resolve_access_token_sgbd failed to get database connection. Reason: ~p.", [Reason]),
										{error, invalid_code} 
								end;
							_ -> 
								ems_logger:error("ems_oauth2_backend resolve_access_token_sgbd failed. Datasource service_datasource not found."),
								{error, invalid_code} 
						end;
					false -> 
						ems_logger:info("ems_oauth2_backend resolve_access_token_sgbd failed. SqlSelect not configured. Token: ~p.", [AccessToken]),
						{error, invalid_code} 
				end,
				T2 = ems_util:get_timestamp(),
				ems_logger:info("ems_oauth2_backend resolve_access_token_sgbd execution time: ~p ms.", [T2 - T1]),
				Result;
			false -> 
				ems_logger:info("ems_oauth2_backend resolve_access_token_sgbd skipped. SGBD persistence disabled. Token: ~p.", [AccessToken]),
				{error, invalid_code} 
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend resolve_access_token_sgbd failed. AccessToken: ~p. Reason: ~p.", [AccessToken, ReasonException]),
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
			ems_logger:error("ems_oauth2_backend revoke_access_code failed. AccessCode: ~p Reason: ~p.", [AccessCode, ReasonException]),
			{error, eparse_revoke_access_code}
	end.


revoke_access_token(AccessToken, _) ->
	try
		case ems_db:get(auth_oauth2_access_token_table, AccessToken) of
			{ok, Record} -> 
				ems_db:delete(Record),
				%% Remove do cache também
				ems_auth_token_cache:invalidate(AccessToken);
			_ -> ok
		end,
		{ok, []}
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend revoke_access_token failed. AccessToken: ~p Reason: ~p.", [AccessToken, ReasonException]),
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
			ems_logger:error("ems_oauth2_backend ems_oauth2_backend revoke_refresh_token exception. RefreshToken: ~p Reason: ~p.", [RefreshToken, ReasonException]),
			{error, eparse_revoke_refresh_token}
	end.
		

get_redirection_uri(Client, _) ->
    case get_client_identity(Client, [])  of
        {ok, #client{redirect_uri = RedirectUri}} -> 
			{ok, RedirectUri};
        _ -> 
			{error, einvalid_uri} 
    end.


verify_redirection_uri(#client{redirect_uri = _RedirUri}, _ClientUri, _) ->
%    case ClientUri =:= RedirUri of
%		true -> 
%			{ok, []};
%		_Error -> 
%			{error, unauthorized_client}
%   end.
{ok, []}.


    
% função criada pois a biblioteca OAuth2 não trata refresh_tokens
authorize_refresh_token(Client, RefreshToken, Scope, State) ->
	try
		case resolve_refresh_token(RefreshToken, []) of
			{ok, {_, [_, {_, ResourceOwner}, _, _]}} -> 
				Result = {ok, {[], #a{client = Client,
							   resowner = ResourceOwner,
							   scope = Scope,
							   state = State,
							   ttl = oauth2_config:expiry_time(password_credentials)
				}}},
				Result;
			Error -> Error
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_oauth2_backend authorize_refresh_token exception. Client: ~p  RefreshToken: ~p. Reason: ~p.", [Client, RefreshToken, ReasonException]),
			{error, eparse_authorize_refresh_token}
	end.

sanitize_context_for_save(Context) when is_list(Context) ->
    [sanitize_context_item_save(Item) || Item <- Context];
sanitize_context_for_save(Context) -> Context.

sanitize_context_for_load(Context) when is_list(Context) ->
    [sanitize_context_item_load(Item) || Item <- Context];
sanitize_context_for_load(Context) -> Context.

% SAVE LOGIC (Backward Compatibility)
% Target User: Size 47
% Target Client: Size 24
sanitize_context_item_save({<<"resource_owner">>, User}) when is_tuple(User), element(1, User) == user ->
    case tuple_size(User) of
        48 -> 
             %ems_logger:info("DEBUG: Sanitizing #user for SAVE. Size 48 -> 47"),
             {<<"resource_owner">>, erlang:delete_element(48, User)};
        49 -> 
             %ems_logger:info("DEBUG: Sanitizing #user for SAVE. Size 49 -> 47"),
             User1 = erlang:delete_element(49, User),
             {<<"resource_owner">>, erlang:delete_element(48, User1)};
        _ ->
             {<<"resource_owner">>, User}
    end;
sanitize_context_item_save({<<"client">>, Client}) when is_tuple(Client), element(1, Client) == client ->
    case tuple_size(Client) of
        25 -> 
             %ems_logger:info("DEBUG: Sanitizing #client for SAVE. Size 25 -> 24"),
             {<<"client">>, erlang:delete_element(25, Client)};
        _ ->
             {<<"client">>, Client}
    end;
sanitize_context_item_save(Item) -> Item.

% LOAD LOGIC (Forward Compatibility)
% Target User: Size 48
% Target Client: Size 25
sanitize_context_item_load({<<"resource_owner">>, User}) when is_tuple(User), element(1, User) == user ->
    case tuple_size(User) of
        47 -> 
             %ems_logger:info("DEBUG: Sanitizing #user for LOAD. Size 47 -> 48"),
             {<<"resource_owner">>, erlang:append_element(User, undefined)};
        49 -> 
             %ems_logger:info("DEBUG: Sanitizing #user for LOAD. Size 49 -> 48"),
             {<<"resource_owner">>, erlang:delete_element(49, User)};
        _ ->
             {<<"resource_owner">>, User}
    end;
sanitize_context_item_load({<<"client">>, Client}) when is_tuple(Client), element(1, Client) == client ->
    % Handle User-Agent first (legacy conversion)
    Client1 = case tuple_size(Client) >= 15 andalso is_binary(element(15, Client)) of
        true -> 
            LegacyUA = parse_user_agent_legacy(element(15, Client)),
            %ems_logger:info("DEBUG: Sanitizing #client.user_agent for LOAD."),
            setelement(15, Client, LegacyUA);
        false -> Client
    end,

    case tuple_size(Client1) of
        24 -> 
             %ems_logger:info("DEBUG: Sanitizing #client for LOAD. Size 24 -> 25"),
             {<<"client">>, erlang:append_element(Client1, undefined)};
        _ ->
             {<<"client">>, Client1}
    end;
sanitize_context_item_load(Item) -> Item.


parse_user_agent_legacy(UserAgentBin) ->
    UA = string:to_lower(binary_to_list(UserAgentBin)),
    %ems_logger:info("DEBUG: parse_user_agent_legacy Input: ~p Lower: ~p", [UserAgentBin, UA]),
    case string:str(UA, "firefox") > 0 of
        true -> browser_firefox;
        false ->
            case string:str(UA, "chrome") > 0 of
                true -> browser_chrome;
                false ->
                    case string:str(UA, "safari") > 0 of
                        true -> browser_safari;
                        false ->
                            case string:str(UA, "msie") > 0 orelse string:str(UA, "trident") > 0 of
                                true -> browser_ie;
                                false ->
                                    case string:str(UA, "edge") > 0 of
                                        true -> browser_edge;
                                        false ->
                                            case string:str(UA, "opera") > 0 of
                                                true -> browser_opera;
                                                false ->
                                                     case string:str(UA, "android") > 0 of
                                                        true -> browser_android;
                                                        false ->
                                                            case string:str(UA, "iphone") > 0 orelse string:str(UA, "ipad") > 0 of
                                                                true -> browser_ios;
                                                                false -> other
                                                             end
                                                     end
                                            end
                                    end
                            end
                    end
            end
    end.
