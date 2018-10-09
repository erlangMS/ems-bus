%%******************************************************************** 
%% @title Module ems_json_loader  
%% @version 1.0.0 %% 
%% @doc Module responsible for load json data from filesystem
%% @author Everton de Vargas Agilar  <evertonagilar@gmail.com> 
%% @copyright ErlangMS Team 
%%********************************************************************

-module(ems_json_loader).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Server API
-export([start/1, stop/0]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3, 
		 last_update/1, is_empty/1, size_table/1, sync/1, sync_full/1, pause/1, resume/1]).

% estado do servidor
-record(state, {name,
				update_checkpoint,
				last_update,
				last_update_param_name,
				middleware,
				filename_service,
				source_type
			}).

-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start(Service = #service{name = Name}) -> 
   	ServerName = erlang:binary_to_atom(Name, utf8),
    gen_server:start_link({local, ServerName}, ?MODULE, Service, []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 
last_update(Server) -> gen_server:call(Server, last_update).
	
is_empty(Server) -> gen_server:call(Server, is_empty).

size_table(Server) -> gen_server:call(Server, size_table).

sync(Server) -> 
	gen_server:cast(Server, sync),
	ok.

sync_full(Server) -> 
	gen_server:cast(Server, sync_full),
	ok.

pause(Server) ->
	gen_server:cast(Server, pause),
	ok.

resume(Server) ->
	gen_server:cast(Server, resume),
	ok.

 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(#service{name = Name, 
			  middleware = Middleware, 
			  filename = FilenameService,
			  start_timeout = StartTimeout,
			  properties = Props}) ->
	LastUpdateParamName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_last_update_param_name">>]), utf8),
	UpdateCheckpoint = maps:get(<<"update_checkpoint">>, Props, ?DATA_LOADER_UPDATE_CHECKPOINT),
	SourceType = binary_to_atom(maps:get(<<"source_type">>, Props, <<"fs">>), utf8),
	erlang:send_after(60000 * 60, self(), check_sync_full),
	State = #state{name = binary_to_list(Name),
				   update_checkpoint = UpdateCheckpoint,
				   last_update_param_name = LastUpdateParamName,
				   last_update = undefined, % sempre recarregar os dados ao iniciar o processo
				   middleware = Middleware,
				   source_type = SourceType,
				   filename_service = FilenameService},
	{ok, State, StartTimeout}.
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(sync, State) -> handle_do_check_load_or_update(State);

handle_cast(sync_full, State) -> handle_do_check_load_or_update(State#state{last_update = undefined});

handle_cast(pause, State = #state{name = Name}) ->
	ems_logger:info("~s paused.", [Name]),
	{noreply, State};

handle_cast(resume, State = #state{name = Name,
								   update_checkpoint = UpdateCheckpoint}) ->
	ems_logger:info("~s resume.", [Name]),
	{noreply, State, UpdateCheckpoint};

handle_cast(_Msg, State = #state{update_checkpoint = UpdateCheckpoint}) ->
	{noreply, State, UpdateCheckpoint}.

handle_call(last_update, _From, State = #state{last_update_param_name = LastUpdateParamName}) ->
	Reply = {ok, ems_db:get_param(LastUpdateParamName)},
	{reply, Reply, State};

handle_call(is_empty, _From, State) ->
	Reply = {ok, do_is_empty(State)},
	{reply, Reply, State};

handle_call(size_table, _From, State) ->
	Reply = {ok, do_size_table(State)},
	{reply, Reply, State};

handle_call(Msg, _From, State) ->
	{reply, Msg, State}.

handle_info(State = #state{update_checkpoint = UpdateCheckpoint}) ->
   {noreply, State, UpdateCheckpoint}.

handle_info(check_sync_full, State = #state{name = Name,
													  update_checkpoint = UpdateCheckpoint}) ->
	{{_, _, _}, {Hour, _, _}} = calendar:local_time(),
	case Hour >= 4 andalso Hour =< 6 of
		true ->
			ems_logger:info("~s force load checkpoint.", [Name]),
			State2 = State#state{last_update = undefined},
			case do_check_load_or_update(State2) of
				{ok, State3} ->
					erlang:send_after(86400 * 1000, self(), check_sync_full),
					{noreply, State3, UpdateCheckpoint};
				{error, _Reason} -> 
					erlang:send_after(86400 * 1000, self(), check_sync_full),
					{noreply, State, UpdateCheckpoint}
			end;
		_ -> 
			erlang:send_after(60000 * 60, self(), check_sync_full),
			{noreply, State, UpdateCheckpoint}
	end;

handle_info(timeout, State) -> handle_do_check_load_or_update(State);

handle_info({_Pid, {error, Reason}}, State = #state{name = Name,
													update_checkpoint = UpdateCheckpoint}) ->
	ems_logger:warn("~s is unable to load or update data. Reason: ~p.", [Name, Reason]),
	{noreply, State, UpdateCheckpoint};
			
handle_info(Msg, State = #state{name = Name, update_checkpoint = UpdateCheckpoint}) ->
	ems_logger:warn("~s unknown message: ~p.", [Name, Msg]),
	{noreply, State, UpdateCheckpoint}.
			
terminate(Reason, #service{name = Name}) ->
    ems_logger:warn("~s was terminated. Reason: ~p.", [Name, Reason]),
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_do_check_load_or_update(State = #state{update_checkpoint = UpdateCheckpoint}) ->
	case do_check_load_or_update(State) of
		{ok, State2} ->	{noreply, State2, UpdateCheckpoint};
		_Error -> {noreply, State, UpdateCheckpoint}
	end.
	

%%====================================================================
%% Internal functions
%%====================================================================


do_check_load_or_update(State = #state{name = Name,
									   last_update_param_name = LastUpdateParamName,
									   last_update = LastUpdate}) ->
	% garante que os dados serão atualizados mesmo que as datas não estejam sincronizadas
	NextUpdate = ems_util:date_dec_minute(calendar:local_time(), 6), 
	LastUpdateStr = ems_util:timestamp_str(),
	Conf = ems_config:getConfig(),
	case LastUpdate == undefined orelse do_is_empty(State) of
		true -> 
			?DEBUG("~s load checkpoint.", [Name]),
			case do_load(LastUpdateStr, Conf, State) of
				ok -> 
					ems_db:set_param(LastUpdateParamName, NextUpdate),
					State2 = State#state{last_update = NextUpdate},
					{ok, State2};
				Error -> Error
			end;
		false ->
			?DEBUG("~s update checkpoint. last update: ~s.", [Name, ems_util:timestamp_str(LastUpdate)]),
			case do_update(LastUpdate, LastUpdateStr, Conf, State) of
				ok -> 
					ems_db:set_param(LastUpdateParamName, NextUpdate),
					State2 = State#state{last_update = NextUpdate},
					{ok, State2};
				Error -> Error
			end
	end.


-spec do_load(tuple(), #config{}, #state{}) -> ok | {error, atom()}.
do_load(CtrlInsert, Conf, State = #state{name = Name,
										 middleware = Middleware,
										 source_type = SourceType}) -> 
	try
		Filename = do_get_filename(State),
		case ems_json_scan:scan(Filename, Conf) of
			{ok, []} -> 
				?DEBUG("~s did not load any record.", [Name]),
				ok;
			{ok, Records} ->
				case do_clear_table(State) of
					ok ->
						do_reset_sequence(State),
						{ok, InsertCount, _, ErrorCount, DisabledCount, SkipCount} = ems_data_pump:data_pump(Records, list_to_binary(CtrlInsert), Conf, Name, Middleware, insert, 0, 0, 0, 0, 0, SourceType, []),
						ems_logger:info("~s sync ~p inserts, ~p disabled, ~p skips, ~p errors.", [Name, InsertCount, DisabledCount, SkipCount, ErrorCount]),
						ok;
					Error ->
						ems_logger:error("~s could not clear table before load data.", [Name]),
						Error
				end;
			Error4 -> 
				ems_logger:warn("~s does not load data from filesystem.", [Name]),
				Error4
		end
	catch
		_Exception:Reason3 -> 
			ems_logger:error("~s load exception error: ~p.", [Name, Reason3]),
			{error, Reason3}
	end.

-spec do_update(tuple(), tuple(), #config{}, #state{}) -> ok | {error, atom()}.
do_update(LastUpdate, CtrlUpdate, Conf, State = #state{name = Name,
													   middleware = Middleware,
													   source_type = SourceType}) -> 
	try
		Filename = do_get_filename(State),
		case ems_json_scan:scan(Filename, Conf) of
			{ok, []} -> 
				?DEBUG("~s did not load any record.", [Name]),
				ok;
			{ok, Records} ->
				{ok, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount} = ems_data_pump:data_pump(Records, list_to_binary(CtrlUpdate), Conf, Name, Middleware, update, 0, 0, 0, 0, 0, SourceType, []),
				% Para não gerar muito log, apenas imprime no log se algum registro foi modificado
				case InsertCount > 0 orelse UpdateCount > 0 orelse ErrorCount > 0 orelse DisabledCount > 0 of
					true ->
						LastUpdateStr = ems_util:timestamp_str(LastUpdate),
						ems_logger:info("~s sync ~p inserts, ~p updates, ~p disabled, ~p skips, ~p errors since ~s.", [Name, InsertCount, UpdateCount, DisabledCount, SkipCount, ErrorCount, LastUpdateStr]);
					false -> ok
				end,
				ok;
			{error, Reason} = Error -> 
				ems_logger:error("~s update data error: ~p.", [Name, Reason]),
				Error
		end
	catch
		_Exception:Reason3 -> 
			ems_logger:error("~s udpate exception error: ~p.", [Name, Reason3]),
			{error, Reason3}
	end.

-spec do_is_empty(#state{}) -> {ok, boolean()}.
do_is_empty(#state{middleware = Middleware, source_type = SourceType}) ->
	apply(Middleware, is_empty, [SourceType]).


-spec do_size_table(#state{}) -> {ok, non_neg_integer()}.
do_size_table(#state{middleware = Middleware, source_type = SourceType}) ->
	apply(Middleware, size_table, [SourceType]).


-spec do_clear_table(#state{}) -> ok | {error, efail_clear_ets_table}.
do_clear_table(#state{middleware = Middleware, source_type = SourceType}) ->
	apply(Middleware, clear_table, [SourceType]).


-spec do_reset_sequence(#state{}) -> ok.
do_reset_sequence(#state{middleware = Middleware, source_type = SourceType}) ->
	apply(Middleware, reset_sequence, [SourceType]).
	
-spec do_get_filename(#state{}) -> string() | list(tuple()).
do_get_filename(#state{filename_service = FilenameService, middleware = Middleware}) ->
	% O nome do arquivo json pode ser obtido tanto do catálogo de serviço quanto do middleware (default)
	case FilenameService of
		<<>> -> apply(Middleware, get_filename, []);
		_ -> FilenameService
	end.
	
