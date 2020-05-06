%%******************************************************************** 
%% @title Module ems_data_loader_ctl  
%% @version 1.0.0 %%
%% @doc Module responsible for load records from database
%% @author Everton de Vargas Agilar  <evertonagilar@gmail.com> 
%% @copyright ErlangMS Team 
%%********************************************************************

-module(ems_data_loader_ctl).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Server API
-export([start/1, stop/0]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3, 
		 permission_to_execute/4, notify_finish_work/9]).

% estado do servidor
-record(state, {}).

-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start(_Service) -> 
	ets:new(ets_dataloader_working_ctl, [set, named_table, public]),
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 

permission_to_execute(DataLoader, [], Operation, WaitCount) -> 
	ets:insert(ets_dataloader_working_ctl, {DataLoader, working, 
											"timestamp", ems_util:timestamp_str(), 
											"operation", Operation, 
											"wait_count", WaitCount,
											"insert_count", 0,
											"update_count", 0,
											"error_count", 0,
											"disable_count", 0,
											"skip_count", 0,
											"last_error", ""}),
	true;
permission_to_execute(DataLoader, [DataLoaderGroup|T], Operation, WaitCount) ->
	case ets:lookup(ets_dataloader_working_ctl, DataLoaderGroup) of
		[] -> permission_to_execute(DataLoader, T, Operation, WaitCount);
		[{_, working, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _}] -> 
			ets:insert(ets_dataloader_working_ctl, {DataLoader, waiting, 
													"timestamp", ems_util:timestamp_str(), 
													"operation", Operation, 
													"wait_count", WaitCount,
													"insert_count", 0,
													"update_count", 0,
													"error_count", 0,
													"disable_count", 0,
													"skip_count", 0,
													"last_error", ""}),
			false;
		_ -> permission_to_execute(DataLoader, T, Operation, WaitCount)
	end.
 
notify_finish_work(DataLoader, Operation, WaitCount, InsertCount, UpdateCount, ErrorCount, DisableCount, SkipCount, LastError) ->
	ets:insert(ets_dataloader_working_ctl, {DataLoader, idle, 
											"timestamp", ems_util:timestamp_str(), 
											"operation", Operation, 
											"wait_count", WaitCount,
											"insert_count", InsertCount,
											"update_count", UpdateCount,
											"error_count", ErrorCount,
											"disable_count", DisableCount,
											"skip_count", SkipCount,
											"last_error", LastError}).
 
 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(_) ->
	{ok, #state{}}.
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_call(Msg, _From, State) ->
	{reply, Msg, State}.
		
handle_info(timeout, State) ->  {noreply, State}.

handle_info(State) -> {noreply, State}.

terminate(Reason, #service{name = Name}) ->
    ems_logger:warn("~s was terminated. Reason: ~p.", [Name, Reason]),
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

	

%%====================================================================
%% Internal functions
%%====================================================================

