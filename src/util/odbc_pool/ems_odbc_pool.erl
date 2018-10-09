%%********************************************************************
%% @title Module ems_odbc_pool
%% @version 1.0.0
%% @doc Provides a pool for ODBC connections
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_odbc_pool).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Server API
-export([start/1, start_link/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

-export([get_connection/1, release_connection/1, connection_pool_size/1, param_query/2, param_query/3, param_query/4]).

-define(SERVER, ?MODULE).

%  State
-record(state, {}). 


%%====================================================================
%% Server API
%%====================================================================

start(_) -> 
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
 
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

stop() ->
    gen_server:cast(?SERVER, shutdown).
 
 
-spec get_connection(#service_datasource{}) -> {ok, #service_datasource{}} | {error, eunavailable_odbc_connection}.
get_connection(Datasource = #service_datasource{id = Id}) ->
	try
		case gen_server:call(?SERVER, {create_connection, Datasource}, 8000) of
			{ok, _Datasource2} = Result ->
				?DEBUG("ems_odbc_pool get_connection from datasource id ~p.", [Id]),
				Result;
			_ -> 
				case gen_server:call(?SERVER, {create_connection, Datasource}, 16000) of
					{ok, _Datasource2} = Result2 ->
						?DEBUG("ems_odbc_pool get_connection from datasource id ~p after the second attempt.", [Id]),
						Result2;
					{error, Reason2} -> 
						?DEBUG("ems_odbc_pool get_connection eunavailable_odbc_connection from datasource id ~p. Reason: ~p.", [Id, Reason2]),
						{error, eunavailable_odbc_connection}
				end
		end
	catch
		_:_ -> %% provavelmente timeout
			try
				case gen_server:call(?SERVER, {create_connection, Datasource}, 16000) of
					{ok, _Datasource3} = Result3 ->
						?DEBUG("ems_odbc_pool get_connection from datasource id ~p after timeout.", [Id]),
						Result3;
					{error, Reason3} -> 
						?DEBUG("ems_odbc_pool get_connection eunavailable_odbc_connection from datasource id ~p. Reason: ~p.", [Id, Reason3]),
						{error, eunavailable_odbc_connection}
				end
			catch 
				_:_ ->
					?DEBUG("ems_odbc_pool get_connection eunavailable_odbc_connection from datasource id ~p. Reason: eodbc_connection_timeout.", [Id]),
					{error, eunavailable_odbc_connection}
			end
	end.


-spec release_connection(#service_datasource{}) -> ok.
release_connection(Datasource = #service_datasource{id = Id}) ->
	try
		gen_server:call(?SERVER, {release_connection, Datasource}, 15000)
	catch 
		_: Reason -> 
			?DEBUG("ems_odbc_pool release_connection exception from datasource id ~p. Reason: ~p.", [Id, Reason]),
			ok
	end.


connection_pool_size(Datasource = #service_datasource{id = Id}) -> 
	try
		gen_server:call(?SERVER, {get_size, Datasource})
	catch
		_ : _ ->
			?DEBUG("ems_odbc_pool connection_pool_size catch timeout exception from datasource id ~p.", [Id]),
			{error, eunavailable_odbc_connection}
	end.


param_query(#service_datasource{id = Id, owner = Owner, timeout = Timeout}, Sql) ->
	try
		gen_server:call(Owner, {param_query, Sql, []}, Timeout)
	catch
		_ : _ ->
			?DEBUG("ems_odbc_pool param_query catch timeout exception from datasource id ~p.", [Id]),
			{error, eunavailable_odbc_connection}
	end.


param_query(#service_datasource{id = Id, owner = Owner, timeout = Timeout}, Sql, Params) ->
	try
		gen_server:call(Owner, {param_query, Sql, Params}, Timeout)
	catch
		_ : _ ->
			?DEBUG("ems_odbc_pool param_query catch timeout exception from datasource id ~p.", [Id]),
			{error, eunavailable_odbc_connection}
	end.

param_query(#service_datasource{id = Id, owner = Owner}, Sql, Params, Timeout) ->
	try
		gen_server:call(Owner, {param_query, Sql, Params}, Timeout)
	catch
		_ : _ ->
			?DEBUG("ems_odbc_pool param_query catch timeout exception from datasource id ~p.", [Id]),
			{error, eunavailable_odbc_connection}
	end.


%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(_Args) ->
	process_flag(trap_exit, true),
    {ok, #state{}}. 
    
handle_cast(shutdown, State) ->
    {stop, normal, State}.

handle_call({release_connection, Datasource}, _From, State) ->
	do_release_connection(Datasource),
	{reply, ok, State};

handle_call({create_connection, Datasource}, {Pid, _Tag}, State) ->
	Reply = do_create_connection(Datasource, Pid),
	{reply, Reply, State};

handle_call({get_size, Datasource}, _From, State) ->
	Reply = get_connection_pool_size(Datasource),
	{reply, Reply, State}.
	
handle_info(State) ->
   {noreply, State}.

% recebe mensagem quando o processo que solicitou a conexão morre
handle_info({_Signal, Ref, process, _Pid2, _Reason}, State) ->
	erlang:demonitor(Ref),
   case erlang:erase(Ref) of
		undefined -> 
			{noreply, State};
		Datasource ->
			do_release_connection(Datasource),
			{noreply, State}
	end;

% recebe mensagem quando o worker do pool morre
handle_info({'EXIT', PidWorker, Reason}, State) ->
   case erlang:erase(PidWorker) of
		undefined -> 
			{noreply, State};
		Datasource ->
			do_remove_pool_when_worker_died(Datasource, Reason),
			{noreply, State}
	end.



terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    

    
%%====================================================================
%% Internal functions
%%====================================================================

do_remove_pool_when_worker_died(#service_datasource{id = Id, 
								   owner = WorkerPid,
								   connection_closed_metric_name = ConnectionClosedMetricName,
								   connection_shutdown_metric_name = ConnectionShutdownMetricName}, Reason) ->
	case Reason of
		normal ->
			Pool = find_pool(Id),
			Pool2 = queue:filter(fun(Item) -> Item#service_datasource.owner /=  WorkerPid end, Pool),
			erlang:put(Id, Pool2),
			ems_db:inc_counter(ConnectionClosedMetricName);
		_ ->
			erlang:put(Id, queue:new()),
			ems_db:inc_counter(ConnectionShutdownMetricName)
	end.
    
			
-spec do_create_connection(#service_datasource{}, pid()) -> {ok, #service_datasource{}} | {error, eunavailable_odbc_connection}.
do_create_connection(Datasource = #service_datasource{id = Id,
													  table_name = TableName,
													  sql = Sql,
													  primary_key = PrimaryKey,
													  max_pool_size = MaxPoolSize,
													  connection_count_metric_name = ConnectionCountMetricName,
													  connection_created_metric_name = ConnectionCreatedMetricName,
													  connection_reuse_metric_name = ConnectionReuseMetricName,
													  connection_unavailable_metric_name = ConnectionUnavailableMetricName,
													  connection_max_pool_size_exceeded_metric_name = ConnectionMaxPoolSizeExceededMetricName}, 
					 PidModule) ->
	try
		Pool = find_pool(Id),
		PoolSize = queue:len(Pool),
		case PoolSize of
			0 ->
				ConnectionCount = ems_db:current_counter(ConnectionCountMetricName),
				case ConnectionCount =< MaxPoolSize of
					true ->
						case ems_odbc_pool_worker:start_link(Datasource) of
							{ok, WorkerPid} ->
								PidModuleRef = erlang:monitor(process, PidModule),
								Datasource2 = ems_odbc_pool_worker:get_datasource(WorkerPid),
								Datasource3 = Datasource2#service_datasource{owner = WorkerPid, 
																			 pid_module = PidModule,
																			 pid_module_ref = PidModuleRef},
								ems_odbc_pool_worker:notify_use(WorkerPid, Datasource3),
								erlang:put(PidModuleRef, Datasource3),
								erlang:put(WorkerPid, Datasource3),
								ems_db:inc_counter(ConnectionCountMetricName),								
								ems_db:inc_counter(ConnectionCreatedMetricName),								
								?DEBUG("ems_odbc_pool do_create_connection start new worker (Ds: ~p Worker: ~p PoolSize: ~p ConnectionCount: ~p).", [Id, Datasource3#service_datasource.conn_ref, PoolSize, ConnectionCount]),
								{ok, Datasource3};
							_ -> 
								ems_db:inc_counter(ConnectionUnavailableMetricName),								
								{error, eunavailable_odbc_connection}
						end;
					false -> 
						ems_db:inc_counter(ConnectionMaxPoolSizeExceededMetricName),
						{error, eodbc_connection_limit}	
				end;
			_ -> 
				{{value, Datasource2}, Pool2} = queue:out(Pool),
				erlang:put(Id, Pool2),
				PidModuleRef = erlang:monitor(process, PidModule),
				Datasource3 = Datasource2#service_datasource{pid_module = PidModule,
															 pid_module_ref = PidModuleRef,
															 table_name = TableName,
															 sql = Sql,
															 primary_key = PrimaryKey},
				WorkerPid = Datasource3#service_datasource.owner,
				ems_odbc_pool_worker:notify_use(WorkerPid, Datasource3),
				erlang:put(PidModuleRef, Datasource3),
				erlang:put(WorkerPid, Datasource3),
				ems_db:inc_counter(ConnectionReuseMetricName),
				ConnectionCount = ems_db:current_counter(ConnectionCountMetricName),
				?DEBUG("ems_odbc_pool do_create_connection reuse worker (Ds: ~p Worker: ~p PoolSize: ~p ConnectionCount: ~p).", [Id, Datasource3#service_datasource.conn_ref, PoolSize, ConnectionCount]),
				{ok, Datasource3}
		end
	catch
		_:_ -> {error, ecreate_odbc_connection}	
	end.

-spec do_release_connection(#service_datasource{}) -> ok.
do_release_connection(Datasource = #service_datasource{id = Id,
													   owner = Owner, 
													   conn_ref = ConnRef,
													   pid_module_ref = PidModuleRef,
													   max_pool_size = MaxPoolSize,
													   connection_count_metric_name = ConnectionCountMetricName}) ->
	ConnectionCount = ems_db:dec_counter(ConnectionCountMetricName),								
	try
		erlang:demonitor(PidModuleRef),
		erlang:erase(PidModuleRef),
		Pool = find_pool(Id),
		PoolSize = queue:len(Pool),
		case erlang:is_process_alive(Owner) of
			true ->
				% Only back to the pool if it did not exceed the connection limit or the connection did not give error
				case (PoolSize < MaxPoolSize) of
					true ->
						case ems_odbc_pool_worker:notify_return_pool(Owner) of
							ok -> 
								Pool2 = queue:in(Datasource#service_datasource{pid_module = undefined, 
																			   pid_module_ref = undefined}, Pool),
								erlang:put(Id, Pool2),
								ok;
							_ ->
								case erlang:is_process_alive(Owner) of
									true -> gen_server:stop(Owner);
									false -> ok
								end,
								ok
						end;
					false -> 
						?DEBUG("ems_odbc_pool do_release_connection shutdown worker due connection limit (Ds: ~p Worker: ~p PoolSize: ~p ConnectionCount: ~p).", [Id, ConnRef, PoolSize, ConnectionCount]),
						case erlang:is_process_alive(Owner) of
							true -> gen_server:stop(Owner);
							false -> ok
						end,
						ok
				end;
			false -> ok
		end
	catch
		_:Reason -> 
			?DEBUG("ems_odbc_pool do_release_connection exception (Ds: ~p Worker: ~p ConnectionCount: ~p Reason: ~p).", [Id, ConnRef, ConnectionCount, Reason]),
			ok
	end.
	

find_pool(Id) ->
	case erlang:get(Id) of
		undefined -> 
			queue:new();
		Pool -> 
			Pool
	end.

get_connection_pool_size(#service_datasource{id = Id}) ->
	Pool = find_pool(Id),
	queue:len(Pool).

