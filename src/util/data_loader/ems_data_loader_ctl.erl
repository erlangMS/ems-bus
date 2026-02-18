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
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3, 
		 permission_to_execute/4, notify_finish_work/9,
		 register_activity/1, is_active/2, get_last_activity/1, register_loader/2]).

% estado do servidor
-record(state, {}).

-define(SERVER, ?MODULE).

-define(ACTIVITY_THRESHOLD, 300000).		% 5 minutes (300.000 ms)

%%====================================================================
%% Server API
%%====================================================================

start(_Service) -> 
	ets:new(ets_dataloader_working_ctl, [set, named_table, public]),
	ets:new(ets_dataloader_activity_ctl, [set, named_table, public]),
	ets:new(ets_dataloader_registry_ctl, [bag, named_table, public]),
	Now = ems_util:get_timestamp(),
	ets:insert(ets_dataloader_activity_ctl, {global, Now}),
	ets:insert(ets_dataloader_activity_ctl, {auth, Now}),
	ets:insert(ets_dataloader_activity_ctl, {catalog, Now}),
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).


register_activity(ModuleActivity) ->
	% A atividade é atribuída a uma TAG para que diferentes loaders
	% possam vigiar apenas atividades relevantes ao seu domínio (ex: auth).
	% Se o ModuleActivity não definir uma tag, usa 'global'.
	ActivityTag = get_activity_tag(ModuleActivity),
	Now = ems_util:get_timestamp(),
	case ets:lookup(ets_dataloader_activity_ctl, ActivityTag) of
		[{_, LastActivity}] when (Now - LastActivity) < ?ACTIVITY_THRESHOLD -> 
			ets:insert(ets_dataloader_activity_ctl, {ActivityTag, Now});
		_ -> 
			ets:insert(ets_dataloader_activity_ctl, {ActivityTag, Now}),
			sync_activity(ActivityTag, ModuleActivity)
	end.


is_active(undefined, _) -> true;
is_active(ActivityTag0, MaxAgeSeconds) ->
	ActivityTag = normalize_tag(ActivityTag0),
	case ets:lookup(ets_dataloader_activity_ctl, ActivityTag) of
		[{_, LastActivity}] -> 
			(ems_util:get_timestamp() - LastActivity) < (MaxAgeSeconds * 1000);
		[] -> false
	end.


get_last_activity(ActivityTag0) ->
	ActivityTag = normalize_tag(ActivityTag0),
	case ets:lookup(ets_dataloader_activity_ctl, ActivityTag) of
		[{_, LastActivity}] -> LastActivity;
		[] -> 0
	end.


register_loader(undefined, _) -> ok;
register_loader(ActivityType, LoaderName) ->
	ems_logger:debug("ems_data_loader_ctl register_loader ~p ~p.", [ActivityType, LoaderName]),
	ets:insert(ets_dataloader_registry_ctl, {ActivityType, LoaderName}).


sync_activity(ActivityTag, ModuleActivity) ->
	case ets:lookup(ets_dataloader_registry_ctl, ActivityTag) of
		[] -> ok;
		Loaders -> 
			[gen_server:cast(LoaderName, sync) || {_, LoaderName} <- Loaders],
			ems_logger:debug("ems_data_loader_ctl sync_activity tag ~p module ~p. Loaders: ~p.", [ActivityTag, ModuleActivity, Loaders]),
			ok
	end.


get_activity_tag(auth) -> auth;
get_activity_tag(catalog) -> catalog;
get_activity_tag(_) -> global.

normalize_tag(Tag) when is_binary(Tag) -> binary_to_atom(Tag, utf8);
normalize_tag(Tag) when is_list(Tag) -> list_to_atom(Tag);
normalize_tag(Tag) -> Tag.


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
		
handle_info(timeout, State) ->  {noreply, State};

handle_info(_Msg, State) -> {noreply, State}.

terminate(Reason, _State) ->
    ems_logger:info("ems_data_loader_ctl was terminated. Reason: ~p.", [Reason]),
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

	

%%====================================================================
%% Internal functions
%%====================================================================

