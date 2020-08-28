%%********************************************************************
%% @title Module ems_odbc_pool_worker
%% @version 1.0.0
%% @doc Module ems_odbc_pool_worker
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_odbc_pool_worker).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Server API
-export([start/1, start_link/1, stop/0, get_datasource/1, last_error/1, notify_use/2, notify_return_pool/1]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%  State
-record(state, {datasource, 
			    last_error, 
			    query_count = 0,
			    check_valid_connection_ref,
			    close_idle_connection_ref}). 


%%====================================================================
%% Server API
%%====================================================================

start(_) -> 
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
 
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

stop() ->
    gen_server:cast(?SERVER, shutdown).
 
get_datasource(Worker) -> gen_server:call(Worker, get_datasource).

notify_use(Worker, Datasource) -> gen_server:call(Worker, {notify_use, Datasource}).

notify_return_pool(Worker) -> 
	try
		gen_server:call(Worker, notify_return_pool)
	catch 
		_:_ -> {error, eunavailable_odbc_connection}
	end.

last_error(Worker) -> gen_server:call(Worker, last_error).


 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(Datasource) -> 
	case do_connect(Datasource) of
		{ok, Datasource2} -> 
			{ok, #state{datasource = Datasource2,
						last_error = undefined,
						query_count = 0,
						check_valid_connection_ref = undefined,
						close_idle_connection_ref = undefined}};
		_Error -> ignore
	end.
	
    
handle_cast(shutdown, State) ->
	do_disconnect(State),
    {stop, normal, State};


handle_cast(_Msg, State) ->
	{noreply, State}.


handle_call({select_count, Sql}, _From, State = #state{query_count = QueryCount}) ->
	case do_select_count(Sql, State) of
		{ok, Result, Datasource} -> 
			{reply, Result, State#state{datasource = Datasource, 
										last_error = undefined,
										query_count = QueryCount + 1}};
		Error -> 
			{reply, Error, State#state{last_error = Error,
									    query_count = QueryCount + 1}}
	end;


handle_call({select, Offset, Limit}, _From, State) ->
	case do_select(Offset, Limit, State) of
		{ok, Result, Datasource} -> 
			{reply, Result, State#state{datasource = Datasource, 
										last_error = undefined}};
		Error -> 
			{reply, Error, State#state{last_error = Error}}
	end;

handle_call({param_query, Sql, Params}, _From, State = #state{query_count = QueryCount}) ->
	case do_param_query(Sql, Params, State) of
		{ok, Result, Datasource} -> 
			{reply, Result, State#state{datasource = Datasource, 
										last_error = undefined,
										query_count = QueryCount + 1}};
		Error -> 
			{reply, Error, State#state{last_error = Error,
									    query_count = QueryCount + 1}}
	end;


handle_call({notify_use, #service_datasource{pid_module = PidModule, 
											 pid_module_ref = PidModuleRef}}, 
			_From,  
		    State = #state{datasource = InternalDatasource,
						   check_valid_connection_ref = CheckValidConnectionRef,
						   close_idle_connection_ref = CloseIdleConnectionRef}) ->
	case CheckValidConnectionRef of
		undefined -> ok;
		_ -> erlang:cancel_timer(CheckValidConnectionRef)
	end,
	case CloseIdleConnectionRef of
		undefined -> ok;
		_ -> erlang:cancel_timer(CloseIdleConnectionRef)
	end,
	Datasource2 = InternalDatasource#service_datasource{pid_module = PidModule,
														pid_module_ref = PidModuleRef},
	{reply, ok, State#state{datasource = Datasource2,
							last_error = undefined,
							check_valid_connection_ref = undefined,
							close_idle_connection_ref = undefined}};

handle_call(notify_return_pool, _From, State = #state{datasource = InternalDatasource = #service_datasource{id = Id,
																											sql_check_valid_connection = SqlCheckValidConnection,
																											check_valid_connection_timeout = CheckValidConnectionTimeout,
																											close_idle_connection_timeout = CloseIdleConnectionTimeout}, 
													  query_count = QueryCount, 
													  last_error = LastError}) ->
	% volta ao pool somente se nenhum erro ocorreu
	case LastError of
		undefined ->
			?DEBUG("ems_odbc_pool_worker notify_return_pool (Ds: ~p QueryCount: ~p).", [Id, QueryCount]),
			case SqlCheckValidConnection =/= undefined andalso SqlCheckValidConnection =/= "" of
				true -> CheckValidConnectionRef = erlang:send_after(CheckValidConnectionTimeout, self(), {check_valid_connection, QueryCount});
				false -> CheckValidConnectionRef = undefined
			end,
			CloseIdleConnectionRef = erlang:send_after(CloseIdleConnectionTimeout, self(), close_idle_connection),
			{reply, ok, State#state{datasource = InternalDatasource#service_datasource{pid_module = undefined,
																					   pid_module_ref = undefined},
									last_error = undefined,
									check_valid_connection_ref = CheckValidConnectionRef,
									close_idle_connection_ref = CloseIdleConnectionRef}};
		{error, Reason} ->
			?DEBUG("ems_odbc_pool_worker notify_return_pool skip due error (Ds: ~p QueryCount: ~p LastError: ~p).", [Id, QueryCount, Reason]),
			{reply, LastError, State}
	end;



handle_call(get_datasource, _From, State) ->
	{reply, State#state.datasource, State};

handle_call(last_error, _From, State) ->
	{reply, State#state.last_error, State}.

handle_info(State) ->
	{noreply, State}.


handle_info({check_valid_connection, QueryCount}, State = #state{datasource = #service_datasource{id = Id, 
																								  pid_module = undefined,
																								  conn_ref = ConnRef,
																								  sql_check_valid_connection = SqlCheckValidConnection,
																								  check_valid_connection_timeout = CheckValidConnectionTimeout}, 
																 query_count = QueryCountNow,
																 close_idle_connection_ref = CurrentCloseIdleConnectionRef,
																 check_valid_connection_ref = CurrentCheckValidConnectionRef}) ->
	case QueryCountNow > QueryCount of
		true -> 
			?DEBUG("ems_odbc_pool_worker check_valid_connection skip due worker reuse (Ds: ~p Worker: ~p timerRef: ~p QueryCount: ~p).", [Id, ConnRef, CurrentCheckValidConnectionRef, QueryCountNow]),
			CheckValidConnectionRef = erlang:send_after(CheckValidConnectionTimeout, self(), {check_valid_connection, QueryCount}),
			{noreply, State#state{check_valid_connection_ref = CheckValidConnectionRef}};
		false ->
			case SqlCheckValidConnection =/= undefined andalso SqlCheckValidConnection =/= "" of
				true ->
					try
						?DEBUG("ems_odbc_pool_worker check_valid_connection (Ds: ~p Worker: ~p timerRef: ~p QueryCount: ~p).", [Id, ConnRef, CurrentCheckValidConnectionRef, QueryCountNow]),
						case odbc:param_query(ConnRef, SqlCheckValidConnection, [], 16000) of
							{error, Reason} ->
								erlang:cancel_timer(CurrentCloseIdleConnectionRef),
								?DEBUG("ems_odbc_pool_worker check_valid_connection failed, shutdown worker immediate (Ds: ~p Worker: ~p timerRef: ~p  QueryCount: ~p Reason: ~p).", [Id, ConnRef, CurrentCheckValidConnectionRef, QueryCountNow, Reason]),
								{stop, shutdown, State#state{close_idle_connection_ref = undefined}};
							_ -> 
								{{_, _, _}, {Hour, _, _}} = calendar:local_time(),
								case not (Hour >= 0 andalso Hour =< 4) of
									true -> CheckValidConnectionRef = erlang:send_after(CheckValidConnectionTimeout * 10, self(), {check_valid_connection, QueryCount});
									false -> CheckValidConnectionRef = erlang:send_after(CheckValidConnectionTimeout, self(), {check_valid_connection, QueryCount})
								end,
								{noreply, State#state{check_valid_connection_ref = CheckValidConnectionRef}}
						end
					catch
						_:Reason2 -> 
							erlang:cancel_timer(CurrentCloseIdleConnectionRef),
							?DEBUG("ems_odbc_pool_worker check_valid_connection exception, shutdown worker immediate (Ds: ~p Worker: ~p timerRef: ~p QueryCount: ~p Reason: ~p).", [Id, ConnRef, CurrentCheckValidConnectionRef, QueryCountNow, Reason2]),
							{stop, shutdown, State#state{close_idle_connection_ref = undefined}}
					end;
				false ->
					{noreply, State}
			end
	end;

handle_info(close_idle_connection, State = #state{datasource = #service_datasource{id = Id, log_show_odbc_pool_activity = LogShowPoolActivity},
												  check_valid_connection_ref = CheckValidConnectionRef,
												  query_count = QueryCount}) ->
   ems_logger:info("ems_odbc_pool_worker close_idle_connection (Ds: ~p QueryCount: ~p).", [Id, QueryCount], LogShowPoolActivity),
   erlang:cancel_timer(CheckValidConnectionRef),
   do_disconnect(State),
   {stop, normal, State#state{close_idle_connection_ref = undefined, 
							  check_valid_connection_ref = undefined}};

handle_info(Msg, State) ->
   ?DEBUG("ems_odbc_pool_worker handle_info unknow message ~p.", [Msg]),
   {noreply, State}.

terminate(Reason, State) ->
    do_disconnect(State),
	?DEBUG("ems_odbc_pool_worker terminate ~p.", [Reason]),   
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% Internal functions
%%====================================================================


do_connect(Datasource = #service_datasource{connection = Connection, type = sqlite, driver = sqlite3}) -> 
	{ok, ConnRef} = esqlite3:open(Connection),
	Datasource2 = Datasource#service_datasource{owner = self(), 
												conn_ref = ConnRef},
	{ok, Datasource2};
do_connect(Datasource = #service_datasource{connection = Connection}) -> 
	try
		case odbc:connect(Connection, [{scrollable_cursors, off}, {timeout, 30000}, {trace_driver, off}, {extended_errors, off}]) of
			{ok, ConnRef}	-> 
				Datasource2 = Datasource#service_datasource{owner = self(), 
															conn_ref = ConnRef},
				{ok, Datasource2};
			{error, {PosixError, _}} -> {error, PosixError};
			{error, Reason} -> {error, Reason}
		end
	catch 
		_Exception:{PosixError2, _} -> {error, PosixError2};
		_Exception2:Reason2 -> {error, Reason2}
	end.

do_disconnect(#state{datasource = #service_datasource{id = Id, conn_ref = ConnRef, type = sqlite, driver = sqlite3}, 
					 query_count = QueryCount}) -> 
	try
		?DEBUG("ems_odbc_pool_worker do_disconnect worker (Ds: ~p QueryCount: ~p).", [Id, QueryCount]),
		esqlite3:close(ConnRef)
	catch
		_:Reason ->	
			?DEBUG("ems_odbc_pool_worker do_disconnect worker exception (Ds: ~p QueryCount: ~p Reason: ~p).", [Id, QueryCount, Reason]),
			ok
	end;
do_disconnect(#state{datasource = #service_datasource{id = Id, conn_ref = ConnRef}, 
					 query_count = QueryCount}) -> 
	try
		?DEBUG("ems_odbc_pool_worker do_disconnect worker (Ds: ~p QueryCount: ~p).", [Id, QueryCount]),
		odbc:disconnect(ConnRef)
	catch
		_:Reason ->	
			?DEBUG("ems_odbc_pool_worker do_disconnect worker exception (Ds: ~p QueryCount: ~p Reason: ~p).", [Id, QueryCount, Reason]),
			ok
	end.

do_param_query(Sql, Params, #state{datasource = Datasource = #service_datasource{conn_ref = ConnRef,
																			     type = sqlite,
																				 driver = sqlite3}}) ->
	Params2 = [hd(V) || {_, V} <- Params],
	case esqlite3:prepare(Sql, ConnRef) of
        {ok, Statement} ->
            ok = esqlite3:bind(Statement, Params2),
            Records = esqlite3:fetchall(Statement),
			Fields = tuple_to_list(esqlite3:column_names(Statement)),
			Fields2 = [?UTF8_STRING(erlang:atom_to_binary(F, utf8)) || F <- Fields],
			%?DEBUG("Sqlite resultset query: ~p.", [Records]),
			{ok, {selected, Fields2, Records}, Datasource};
        Error -> Error
    end;
do_param_query(Sql, Params, #state{datasource = Datasource = #service_datasource{id = Id,
																				 conn_ref = ConnRef,
																				 timeout = Timeout}}) ->
	try
		case odbc:param_query(ConnRef, Sql, Params, Timeout) of
			{error, Reason} ->
				ems_logger:error("ems_odbc_pool_worker param_query failed (Ds: ~p Reason: ~p)\n\tSQL: ~s", [Id, Reason, Sql]),
				case ems_db:is_database_in_restricted_mode(Reason) of	
					true ->  {error, eodbc_restricted_connection};
					false -> {error, eodbc_connection_closed}
				end;
			{selected, Fields1, Result1} -> 
				{ok, {selected, [?UTF8_STRING(F) || F <- Fields1], Result1}, Datasource};
			{updated, _RowCount} = Result -> {ok, Result, Datasource}
		end
	catch
		_:timeout -> 
			ems_logger:error("ems_odbc_pool_worker param_query timeout (Ds: ~p)\n\tSQL: ~s.", [Id, Sql]),
			{error, eodbc_connection_timeout};
		_:Reason2 -> 
			ems_logger:error("ems_odbc_pool_worker param_query exception (Ds: ~p Reason: ~p)\n\tSQL: ~s", [Id, Reason2, Sql]),
			{error, eodbc_invalid_connection}
	end.


do_select_count(Sql, #state{datasource = Datasource = #service_datasource{conn_ref = ConnRef,
																		 timeout = Timeout}}) ->
	Result = odbc:select_count(ConnRef, Sql, Timeout),
	{ok, Result, Datasource}.
    
do_select(Offset, Limit, #state{datasource = Datasource = #service_datasource{id = Id, 
																			  conn_ref = ConnRef}}) ->
	try
		case odbc:select(ConnRef, Offset, Limit) of
			{error, Reason} ->
				ems_logger:error("ems_odbc_pool_worker select failed (Ds: ~p Reason: ~p Offset: ~p  Limit: ~p)", [Id, Reason, Offset, Limit]),
				{error, eodbc_connection_closed};
			{selected, Fields1, Result1} -> 
				{ok, {selected, [?UTF8_STRING(F) || F <- Fields1], Result1}, Datasource}
		end
	catch
		_:timeout -> 
			{error, eodbc_connection_timeout};
		_:Reason2 -> 
			ems_logger:error("ems_odbc_pool_worker select failed (Ds: ~p Reason: ~p Offset: ~p  Limit: ~p)", [Id, Reason2, Offset, Limit]),
			{error, eodbc_invalid_connection}
	end.
						
