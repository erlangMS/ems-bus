-module(ems_bus_sup).

-behaviour(supervisor).

-include("../include/ems_schema.hrl").
-include("../include/ems_config.hrl").

%% Supervisor callbacks
-export([start_link/1, init/1]).
-export([start_process/1, start_process_sup/1]).


%% ===================================================================
%% API functions
%% ===================================================================

start_link(Args) ->
	supervisor:start_link({local,?MODULE}, ?MODULE, Args).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
	KernelServices = ems_catalog_lookup:list_kernel_catalog(),
    PoolSpecs = lists:foldl(
		fun(S = #service{name = WorkerName, 
						  pool_size = PoolSize, 
						  pool_max = PoolMax, 
						  module = Worker}, Acc) ->
			% Check if the module exists and exports start/1
			case code:ensure_loaded(Worker) of
				{module, Worker} ->
					case erlang:function_exported(Worker, start, 1) of
						true ->
							WorkerNameAtom = list_to_atom(binary_to_list(WorkerName)),
							Child = case PoolMax == 1 of
								true -> 
									{WorkerNameAtom,
										{?MODULE, start_process, [[Worker, start, S]]},
										permanent, 10000, worker,  [WorkerNameAtom]
									};
								false ->
									{WorkerNameAtom, 
										{?MODULE, start_process_sup, [[poolboy, 
																	   start_link, 
																	   [[{strategy, fifo},
																		 {name, {local, WorkerNameAtom}},
																		 {worker_module, Worker},
																		 {size, PoolSize},
																		 {max_overflow, PoolMax}], S]
																	   ]]},
										 permanent, 10000, worker, [poolboy]
									}
							end,
							[Child | Acc];
						false ->
							ems_logger:warn("ems_bus_sup skipped service ~p: module ~p does not export start/1.", [WorkerName, Worker]),
							Acc
					end;
				_ ->
					ems_logger:warn("ems_bus_sup skipped service ~p: module ~p not found.", [WorkerName, Worker]),
					Acc
			end
		end, [], KernelServices),
	{ok, {{one_for_one, 10, 10}, lists:reverse(PoolSpecs)}}.
	

start_process([Module, Function, Service = #service{name = WorkerName}]) ->
	ems_logger:info("Start ~s.", [binary_to_list(WorkerName)]),
	Reply = apply(Module, Function, [Service]),
	Reply.
	
start_process_sup([Module, Function, Args = [[_,
											  {name, {local, WorkerNameAtom}},
											  _, 
											  {size, PoolSize}, 
											  {max_overflow, PoolMax}], 
											_]]) ->
	ems_logger:info("Start ~p with ~p workers (Max ~p workers).", [WorkerNameAtom, PoolSize, PoolMax]),
	Reply = apply(Module, Function, Args),
	Reply.

