%%******************************************************************** 
%% @title Module ems_data_loader  
%% @version 1.0.0 %%
%% @doc Module responsible for load records from database
%% @author Everton de Vargas Agilar  <evertonagilar@gmail.com> 
%% @copyright ErlangMS Team 
%%********************************************************************

-module(ems_data_loader).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

%% Server API
-export([start/1, stop/0]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3, 
		 last_update/1, is_empty/1, size_table/1, sync/1, sync_full/1, pause/1, resume/1]).

% estado do servidor
-record(state, {name,
			    datasource,
				update_checkpoint,
				check_remove_records_checkpoint,
				timeout_on_error,
				last_update,
				last_update_param_name,
				sql_load,
				sql_update,
				sql_count,
				sql_ids,
				middleware,
				fields,
				check_count_checkpoint_metric_name,
				check_remove_checkpoint_metric_name,
				sync_full_checkpoint_metric_name,
				load_checkpoint_metric_name,
				update_checkpoint_metric_name,
				error_checkpoint_metric_name,
				insert_metric_name,
				update_metric_name,
				update_miss_metric_name,
				error_metric_name,
				disable_metric_name,
				skip_metric_name,
				source_type,
				loading,
				allow_clear_table_full_sync,
				group,
				wait_count,
				insert_count,
				update_count,
				error_count,
				disable_count,
				skip_count
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

	
get_timeout_wait(WaitCount) ->
	Result = 4000 - (WaitCount * 100),
	case Result < 500 of
		true -> 500;
		false -> Result
	end.
 
init(#service{name = Name, 
			  datasource = Datasource, 
			  middleware = Middleware, 
			  start_timeout = StartTimeout,
			  properties = Props}) ->
	NameStr = binary_to_list(Name),
	LastUpdateParamName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_last_update_param_name">>]), utf8),
	LastUpdate = ems_db:get_param(LastUpdateParamName),
	UpdateCheckpoint = maps:get(<<"update_checkpoint">>, Props, ?DATA_LOADER_UPDATE_CHECKPOINT),
	CheckRemoveRecords = ems_util:parse_bool(maps:get(<<"check_remove_records">>, Props, false)),
	CheckRemoveRecordsCheckpoint0 = maps:get(<<"check_remove_records_checkpoint">>, Props, ?DATA_LOADER_UPDATE_CHECKPOINT),
	case CheckRemoveRecordsCheckpoint0 < UpdateCheckpoint of
		true -> CheckRemoveRecordsCheckpoint = UpdateCheckpoint + 5000 + rand:uniform(30000);
		false -> CheckRemoveRecordsCheckpoint = CheckRemoveRecordsCheckpoint0 + rand:uniform(30000)
	end,
	SqlLoad = string:trim(binary_to_list(maps:get(<<"sql_load">>, Props, <<>>))),
	SqlUpdate = string:trim(binary_to_list(maps:get(<<"sql_update">>, Props, <<>>))),
	SqlCount = re:replace(SqlLoad, "select (.+)( from.+)( order by.+)?","select count(1)\\2", [{return,list}]),
	SqlIds = re:replace(SqlLoad, "select ([^,]+),(.+)( from.+)( order by.+)?", "select \\1 \\3", [{return,list}]),
	Fields = maps:get(<<"fields">>, Props, <<>>),
	SourceType = binary_to_atom(maps:get(<<"source_type">>, Props, <<"db">>), utf8),
	TimeoutOnError = maps:get(<<"timeout_on_error">>, Props, 20000) + rand:uniform(10000),
	SyncFullCheckpointMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_full_checkpoint">>]), utf8),
	CheckCountCheckpointMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_check_count_checkpoint">>]), utf8),
	CheckRemoveCheckpointMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_check_remove_checkpoint">>]), utf8),
	LoadCheckpointMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_load_checkpoint">>]), utf8),
	UpdateCheckpointMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_update_checkpoint">>]), utf8),
	ErrorCheckpointMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_error_checkpoint">>]), utf8),
	InsertMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_inserts">>]), utf8),
	UpdateMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_updates">>]), utf8),
	UpdateMissMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_update_miss">>]), utf8),
	ErrorsMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_errors">>]), utf8),
	DisabledMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_disabled">>]), utf8),
	SkipMetricName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_skip">>]), utf8),
	GroupDataLoader = lists:delete(NameStr, ems_util:binlist_to_list(maps:get(<<"group">>, Props, []))),
	erlang:send_after(60000 * 60, self(), check_sync_full),
	case CheckRemoveRecords andalso CheckRemoveRecordsCheckpoint > 0 of
		true -> erlang:send_after(CheckRemoveRecordsCheckpoint + 90000 + rand:uniform(10000), self(), check_count_records);
		false -> ok
	end,
	State = #state{name = NameStr,
				   datasource = Datasource, 
				   update_checkpoint = UpdateCheckpoint,
				   last_update_param_name = LastUpdateParamName,
				   last_update = LastUpdate,
				   check_remove_records_checkpoint = CheckRemoveRecordsCheckpoint,
				   sql_load = SqlLoad,
				   sql_update = SqlUpdate,
				   sql_count = SqlCount,
				   sql_ids = SqlIds,
				   middleware = Middleware,
				   fields = Fields,
				   timeout_on_error = TimeoutOnError,
   				   check_count_checkpoint_metric_name = CheckCountCheckpointMetricName,
   				   check_remove_checkpoint_metric_name = CheckRemoveCheckpointMetricName,
   				   sync_full_checkpoint_metric_name = SyncFullCheckpointMetricName,
   				   load_checkpoint_metric_name = LoadCheckpointMetricName,
				   update_checkpoint_metric_name = UpdateCheckpointMetricName,
				   error_checkpoint_metric_name = ErrorCheckpointMetricName,
				   insert_metric_name = InsertMetricName,
				   update_metric_name = UpdateMetricName,
				   update_miss_metric_name = UpdateMissMetricName,
				   error_metric_name = ErrorsMetricName,
				   disable_metric_name = DisabledMetricName,
				   skip_metric_name = SkipMetricName,
				   source_type = SourceType,
				   loading = true,
				   allow_clear_table_full_sync = false,
				   group = GroupDataLoader,
				   wait_count = 0,
				   insert_count = 0,
				   update_count = 0,
				   error_count = 0,
				   disable_count = 0,
				   skip_count = 0
},
	{ok, State, StartTimeout}.
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(sync, State) -> handle_do_check_load_or_update_checkpoint(State);

handle_cast(sync_full, State = #state{sync_full_checkpoint_metric_name = SyncFullCheckpointMetricName}) -> 
	ems_db:inc_counter(SyncFullCheckpointMetricName),
	handle_do_check_load_or_update_checkpoint(State#state{last_update = undefined, 
														  allow_clear_table_full_sync = true});

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
											update_checkpoint = UpdateCheckpoint,
											timeout_on_error = TimeoutOnError,
											sync_full_checkpoint_metric_name = SyncFullCheckpointMetricName,
											error_checkpoint_metric_name = ErrorCheckpointMetricName,
											loading = Loading,
											group = GroupDataLoader,
											wait_count = WaitCount
										}) ->
		{{_, _, _}, {Hour, _, _}} = calendar:local_time(),
		case (Hour == 6 orelse Hour == 10 orelse Hour == 13 orelse Hour == 18 orelse Hour == 22) of
			true ->
				?DEBUG("~s handle check_sync_full execute now.", [Name]),
				case not Loading andalso ems_data_loader_ctl:permission_to_execute(Name, GroupDataLoader, check_sync_full, WaitCount) of
					true ->
						ems_db:inc_counter(SyncFullCheckpointMetricName),
						ems_logger:info("~s sync full checkpoint now.", [Name]),
						State2 = State#state{last_update = undefined,
											 allow_clear_table_full_sync = (Hour == 6)},  % limpar a tabela somente às 6h da manhã
						case do_check_load_or_update_checkpoint(State2) of
							{ok, State3 = #state{insert_count = InsertCount, update_count = UpdateCount, error_count = ErrorCount, disable_count = DisableCount, skip_count = SkipCount}} ->
								ems_data_loader_ctl:notify_finish_work(Name, check_sync_full, WaitCount, InsertCount, UpdateCount, ErrorCount, DisableCount, SkipCount, undefined),
								ems_logger:info("~s sync full checkpoint successfully", [Name]),
								erlang:send_after(3600000, self(), check_sync_full),
								{noreply, State3#state{wait_count = 0}, UpdateCheckpoint};
							{error, Reason} -> 
								ems_data_loader_ctl:notify_finish_work(Name, check_sync_full, WaitCount, 0, 0, 0, 0, 0, Reason),
								ems_db:inc_counter(ErrorCheckpointMetricName),
								erlang:send_after(3600000, self(), check_sync_full),
								ems_logger:error("~s sync full wait ~pms for next checkpoint while has database connection error. Reason: ~p.", [Name, TimeoutOnError, Reason]),
								{noreply, State#state{wait_count = 0}, TimeoutOnError}
						end;
					false ->
						TimeoutWait = get_timeout_wait(WaitCount),
						ems_logger:warn("~s handle check_sync_full wait ~pms to execute (WaitCount: ~p).", [Name, TimeoutWait, WaitCount]),
						erlang:send_after(TimeoutWait, self(), check_sync_full),
						{noreply, State#state{wait_count = WaitCount + 1}, UpdateCheckpoint}
				end;
			_ -> 
				ems_logger:info("~s skip sync full checkpoint due to the programmed time window.", [Name]),
				erlang:send_after(60000 * 15, self(), check_sync_full),
				{noreply, State, UpdateCheckpoint}
		end;

handle_info(timeout, State) -> 
	handle_do_check_load_or_update_checkpoint(State);

handle_info(check_count_records, State = #state{name = Name,
												update_checkpoint = UpdateCheckpoint,
											    timeout_on_error = TimeoutOnError,
											    check_remove_records_checkpoint = CheckRemoveRecordsCheckpoint,
											    error_checkpoint_metric_name = ErrorCheckpointMetricName,
											    loading = Loading,
											    group = GroupDataLoader,
											    wait_count = WaitCount}) ->
	?DEBUG("~s handle check_count_records execute now.", [Name]),
	case not Loading andalso ems_data_loader_ctl:permission_to_execute(Name, GroupDataLoader, check_count_records, WaitCount) of
		true ->
			case do_check_count_checkpoint(State) of
				{ok, State2} -> 
					ems_data_loader_ctl:notify_finish_work(Name, check_count_records, WaitCount, 0, 0, 0, 0, 0, undefined),
					erlang:send_after(CheckRemoveRecordsCheckpoint, self(), check_count_records),
					{noreply, State2#state{wait_count = 0}, UpdateCheckpoint};
				{error, Reason} -> 
					ems_data_loader_ctl:notify_finish_work(Name, check_count_records, WaitCount, 0, 0, 0, 0, 0, Reason),
					ems_db:inc_counter(ErrorCheckpointMetricName),
					erlang:send_after(CheckRemoveRecordsCheckpoint, self(), check_count_records),
					?DEBUG("~s check_count_records wait ~pms for next checkpoint while has database connection error. Reason: ~p.", [Name, TimeoutOnError, Reason]),
					{noreply, State#state{wait_count = 0}, TimeoutOnError}
			end;
		false ->
			TimeoutWait = get_timeout_wait(WaitCount),
			?DEBUG("~s handle check_count_records wait ~pms to execute.", [Name, TimeoutWait]),
			erlang:send_after(TimeoutWait, self(), check_count_records),
			{noreply, State#state{wait_count = WaitCount + 1}, UpdateCheckpoint}
	end;

handle_info({_Pid, {error, _Reason}}, State = #state{timeout_on_error = TimeoutOnError}) ->
	{noreply, State, TimeoutOnError};
			
handle_info(_Msg, State = #state{timeout_on_error = TimeoutOnError}) ->
	{noreply, State, TimeoutOnError}.
		
terminate(Reason, #service{name = Name}) ->
    ems_logger:warn("~s was terminated. Reason: ~p.", [Name, Reason]),
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_do_check_load_or_update_checkpoint(State = #state{name = Name,
														 update_checkpoint = UpdateCheckpoint,
														 timeout_on_error = TimeoutOnError,
														 error_checkpoint_metric_name = ErrorCheckpointMetricName,
														 loading = Loading,
														 group = DataLoaderGroup,
														 wait_count = WaitCount}) ->
	?DEBUG("~s handle_do_check_load_or_update_checkpoint execute now.", [Name]),
	case ems_data_loader_ctl:permission_to_execute(Name, DataLoaderGroup, check_load_or_update_checkpoint, WaitCount) of
		true ->
			case do_check_load_or_update_checkpoint(State) of
				{ok, State2 = #state{insert_count = InsertCount, update_count = UpdateCount, error_count = ErrorCount, disable_count = DisableCount, skip_count = SkipCount}} ->
					do_after_load_or_update_checkpoint(State2),
					ems_data_loader_ctl:notify_finish_work(Name, check_load_or_update_checkpoint, WaitCount, InsertCount, UpdateCount, ErrorCount, DisableCount, SkipCount, undefined),
					case Loading of
						true -> {noreply, State2#state{wait_count = 0}, UpdateCheckpoint + 60000};
						false -> {noreply, State2#state{wait_count = 0}, UpdateCheckpoint}
					end;
				{error, Reason} -> 
					ems_data_loader_ctl:notify_finish_work(Name, check_count_records, WaitCount, 0, 0, 0, 0, 0, Reason),
					ems_db:inc_counter(ErrorCheckpointMetricName),
					?DEBUG("~s do_check_load_or_update_checkpoint wait ~pms for next checkpoint while has database connection error. Reason: ~p.", [Name, TimeoutOnError, Reason]),
					{noreply, State#state{wait_count = 0}, TimeoutOnError}
			end;
		false ->
			TimeoutWait = get_timeout_wait(WaitCount),
			?DEBUG("~s handle_do_check_load_or_update_checkpoint wait ~pms to execute.", [Name, TimeoutWait]),
			{noreply, State#state{wait_count = WaitCount + 1}, TimeoutWait}
	end.
	

%%====================================================================
%% Internal functions
%%====================================================================


do_check_count_checkpoint(State = #state{name = Name,
										 datasource = Datasource,
										 sql_count = SqlCount,
										 sql_ids = SqlIds,
										 sql_update = SqlUpdate,
										 check_count_checkpoint_metric_name = CheckCountCheckpointMetricName,
										 check_remove_checkpoint_metric_name = CheckRemoveCheckpointMetricName}) ->
	try
		?DEBUG("~s do_check_count_checkpoint execute now.", [Name]),
		ems_db:inc_counter(CheckCountCheckpointMetricName),
		case ems_odbc_pool:get_connection(Datasource) of
			{ok, Datasource2} -> 
				Result = case ems_odbc_pool:param_query(Datasource2, SqlCount, []) of
					{_, _, [{CountDBTable}]} ->
						CountMnesiaTable = do_size_table(State),
						case CountDBTable > CountMnesiaTable of
							true -> CountDiff = CountDBTable - CountMnesiaTable;
							false -> CountDiff = CountMnesiaTable - CountDBTable
						end,
						?DEBUG("~s do_check_count_checkpoint CountDB ~p  CountMnesia ~p  Diff ~p.", [Name, CountDBTable, CountMnesiaTable, CountDiff]),
						if 
							% Atenção: Quando fazer carga completa da tabela
							% 1) Quando a diferença de registros entre as duas tabelas é muito grande, é melhor fazer uma carga completa
							% 2) Quando a quantidade de registros no mnesia é menor que a que está no banco e o parâmetro sql_update não foi informado
							(CountMnesiaTable > 10000 andalso CountDiff > 1000) orelse (CountMnesiaTable < CountDBTable andalso SqlUpdate == "") ->
								?DEBUG("~s do_check_count_checkpoint sync full (Diff ~p).", [Name, CountDiff]),
								ems_odbc_pool:release_connection(Datasource2),
								% Carregar todos os dados novamente
								case do_check_load_or_update_checkpoint(State#state{last_update = undefined,
									  											    allow_clear_table_full_sync = false}) of
									 {ok, State2} ->
										% Depois remover os registros apagados. Para isso,
										% é necessário invocar novamente do_check_count_checkpoint pois algumas tabelas (como telefone), 
										% os registros trocam de Ids já que a aplicação ao salvar a lista de itens, 
										% pode ter implementado remover tudo no banco e adicionar novamente
										do_check_count_checkpoint(State2);
									 _ ->
										{ok, State}
								end;
							% Se existe menos registros no banco de dados que o que está cadastrado no mnesia
							CountMnesiaTable > CountDBTable ->
								ems_db:inc_counter(CheckRemoveCheckpointMetricName),
								?DEBUG("~s do_check_count_checkpoint get ids from table...", [Name]),
								case ems_odbc_pool:param_query(Datasource2, SqlIds, []) of
									{_, _, Result2} ->
										ems_odbc_pool:release_connection(Datasource2),
										Codigos = [N || {N} <- Result2],
										RemoveCount = do_check_remove_records(Codigos, State),
										case RemoveCount > 0 of
											true -> 
												?DEBUG("~s deletes ~p records.", [Name, RemoveCount]),
												case SqlUpdate == "" of
													true ->
														% Depois remover os registros apagados, é necessário invocar 
														% novamente do_check_load_or_update_checkpoint pois algumas tabelas (como telefone), 
														% os registros trocam de Ids já que a aplicação ao salvar a lista de itens, 
														% pode ter implementado remover tudo no banco e adicionar novamente
														do_check_load_or_update_checkpoint(State#state{last_update = undefined,
																										allow_clear_table_full_sync = false});
													false -> ok
												end;
											false -> ok
										end,
										{ok, State};
									Error3 -> 
										ems_odbc_pool:release_connection(Datasource2),
										?DEBUG("~s do_check_count_checkpoint exception to execute sql ~p.", [Name, SqlIds]),
										Error3
								end;
							true ->
								ems_odbc_pool:release_connection(Datasource2),
								?DEBUG("~s do_check_count_checkpoint skip remove records.", [Name]),
								{ok, State}
						end;
					Error4 -> 
						ems_odbc_pool:release_connection(Datasource2),
						?DEBUG("~s do_check_count_checkpoint exception to execute sql ~p. Reason: ~p.", [Name, SqlCount, Error4]),
						Error4
				end,
				Result;
			Error5 -> 
				?DEBUG("~s do_check_count_checkpoint has no connection to check counts.", [Name]),
				Error5
		end
	catch
		_Exception:Reason3 -> 
			ems_logger:error("~s do_check_count_checkpoint check count exception error: ~p.", [Name, Reason3]),
			{error, Reason3}
	end.


do_check_load_or_update_checkpoint(State = #state{name = Name,
												  last_update_param_name = LastUpdateParamName,
												  last_update = LastUpdate}) ->
	% garante que os dados serão atualizados mesmo que as datas não estejam sincronizadas
	NextUpdate = ems_util:date_dec_minute(calendar:local_time(), 240), 
	LastUpdateStr = ems_util:timestamp_str(),
	Conf = ems_config:getConfig(),
	case LastUpdate == undefined orelse do_is_empty(State) of
		true -> 
			?DEBUG("~s do_check_load_or_update_checkpoint load checkpoint.", [Name]),
			case do_load(LastUpdateStr, Conf, State) of
				{ok, State2} -> 
					ems_db:set_param(LastUpdateParamName, NextUpdate),
					State3 = State2#state{last_update = NextUpdate, 
										  loading = false,
										  allow_clear_table_full_sync = false},
					{ok, State3};
				Error -> Error
			end;
		false ->
			?DEBUG("~s do_check_load_or_update_checkpoint update checkpoint.", [Name]),
			case do_update(LastUpdate, LastUpdateStr, Conf, State) of
				{ok, State2} -> 
					ems_db:set_param(LastUpdateParamName, NextUpdate),
					State3 = State2#state{last_update = NextUpdate, 
										  loading = false,
										  allow_clear_table_full_sync = false},
					{ok, State3};
				Error -> Error
			end
	end.


-spec do_load(tuple(), #config{}, #state{}) -> ok | {error, atom()}.
do_load(CtrlInsert, Conf, State = #state{datasource = Datasource,
										 name = Name,
										 middleware = Middleware,
										 sql_load = SqlLoad,
										 fields = Fields,
										 load_checkpoint_metric_name = LoadCheckpointMetricName,
										 insert_metric_name = InsertMetricName,
										 error_metric_name = ErrorsMetricName,
										 disable_metric_name = DisabledMetricName,
										 skip_metric_name = SkipMetricName,
										 source_type = SourceType,
										 allow_clear_table_full_sync = AllowClearTableFullSync}) -> 
	try
		?DEBUG("~s do_load execute.", [Name]),
		ems_db:inc_counter(LoadCheckpointMetricName),
		case ems_odbc_pool:get_connection(Datasource) of
			{ok, Datasource2} -> 
				Result = case ems_odbc_pool:param_query(Datasource2, SqlLoad, []) of
					{_, _, Records} ->
						ems_odbc_pool:release_connection(Datasource2),
						case AllowClearTableFullSync of
							true ->
								case do_clear_table(State) of
									ok ->
										do_reset_sequence(State),
										{ok, InsertCount, _, ErrorCount, DisabledCount, SkipCount} = ems_data_pump:data_pump(Records, list_to_binary(CtrlInsert), Conf, Name, Middleware, insert, 0, 0, 0, 0, 0, SourceType, Fields),
										ems_logger:info("~s sync full ~p inserts, ~p disabled, ~p skips, ~p errors.", [Name, InsertCount, DisabledCount, SkipCount, ErrorCount]),
										ems_db:counter(InsertMetricName, InsertCount),
										ems_db:counter(ErrorsMetricName, ErrorCount),
										ems_db:counter(DisabledMetricName, DisabledCount),
										ems_db:counter(SkipMetricName, SkipCount),
										{ok, State#state{insert_count = InsertCount,
														 error_count = ErrorCount,
														 disable_count = DisabledCount,
														 skip_count = SkipCount}};
									Error ->
										ems_logger:error("~s do_load could not clear table before load data.", [Name]),
										Error
								end;
							false ->
								{ok, InsertCount, _, ErrorCount, DisabledCount, SkipCount} = ems_data_pump:data_pump(Records, list_to_binary(CtrlInsert), Conf, Name, Middleware, insert, 0, 0, 0, 0, 0, SourceType, Fields),
								ems_logger:info("~s sync ~p inserts, ~p disabled, ~p skips, ~p errors.", [Name, InsertCount, DisabledCount, SkipCount, ErrorCount]),
								ems_db:counter(InsertMetricName, InsertCount),
								ems_db:counter(ErrorsMetricName, ErrorCount),
								ems_db:counter(DisabledMetricName, DisabledCount),
								ems_db:counter(SkipMetricName, SkipCount),
								{ok, State#state{insert_count = InsertCount,
												 update_count = 0,
												 error_count = ErrorCount,
												 disable_count = DisabledCount,
												 skip_count = SkipCount}}

						end;
					{error, Reason2} = Error2 -> 
						ems_odbc_pool:release_connection(Datasource2),
						?DEBUG("~s do_load failed to execute sql ~p. Reason: ~p.", [Name, SqlLoad, Reason2]),
						Error2
				end,
				Result;
			{error, Reason3} = Error3 -> 
				ems_logger:warn("~s do_load failed to get connection. Reason: ~p.", [Name, Reason3]),
				Error3
		end
	catch
		_Exception:Reason4 -> 
			ems_logger:error("~s do_load exception. Reason: ~p.", [Name, Reason4]),
			{error, Reason4}
	end.

-spec do_update(tuple(), tuple(), #config{}, #state{}) -> ok | {error, atom()}.
do_update(LastUpdate, CtrlUpdate, Conf, State = #state{datasource = Datasource,
													   name = Name,
													   middleware = Middleware,
													   sql_update = SqlUpdate,
													   fields = Fields,
													   update_checkpoint_metric_name = UpdateCheckpointMetricName,
													   insert_metric_name = InsertMetricName,
													   update_metric_name = UpdateMetricName,
													   update_miss_metric_name = UpdateMissMetricName,
													   error_metric_name = ErrorsMetricName,
													   disable_metric_name = DisabledMetricName,
													   skip_metric_name = SkipMetricName,
													   source_type = SourceType}) -> 
	try
		% do_update is optional
		case SqlUpdate =/= "" of
			true ->
				?DEBUG("~s do_update execute.", [Name]),
				ems_db:inc_counter(UpdateCheckpointMetricName),
				case ems_odbc_pool:get_connection(Datasource) of
					{ok, Datasource2} -> 
						{{Year, Month, Day}, {Hour, Min, _}} = LastUpdate,
						DateInitial = {{Year, Month, Day}, {Hour, Min, 0}},
						Params = [{sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]}],
						Result = case ems_odbc_pool:param_query(Datasource2, SqlUpdate, Params) of
							{_,_,[]} -> 
								ems_odbc_pool:release_connection(Datasource2),
								ems_db:inc_counter(UpdateMissMetricName),
								?DEBUG("~s do_update has no records to update.", [Name]),
								{ok, State#state{insert_count = 0,
												 error_count = 0,
												 disable_count = 0,
												 skip_count = 0}};
							{_, _, Records} ->
								ems_odbc_pool:release_connection(Datasource2),
								{ok, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount} = ems_data_pump:data_pump(Records, list_to_binary(CtrlUpdate), Conf, Name, Middleware, update, 0, 0, 0, 0, 0, SourceType, Fields),
								% Para não gerar muito log, apenas imprime no log se algum registro foi modificado
								case InsertCount > 0 orelse UpdateCount > 0 orelse ErrorCount > 0 orelse DisabledCount > 0 of
									true ->
										ems_db:counter(InsertMetricName, InsertCount),
										ems_db:counter(UpdateMetricName, UpdateCount),
										ems_db:counter(ErrorsMetricName, ErrorCount),
										ems_db:counter(DisabledMetricName, DisabledCount),
										ems_logger:info("~s sync ~p inserts, ~p updates, ~p disabled, ~p skips, ~p errors since ~s.", [Name, InsertCount, UpdateCount, DisabledCount, SkipCount, ErrorCount, ems_util:timestamp_str(LastUpdate)]);
									false -> 
										?DEBUG("~s sync ~p inserts, ~p updates, ~p disabled, ~p skips, ~p errors since ~s.", [Name, InsertCount, UpdateCount, DisabledCount, SkipCount, ErrorCount, ems_util:timestamp_str(LastUpdate)]),
										ok
								end,
								ems_db:counter(SkipMetricName, SkipCount),
								{ok, State#state{insert_count = InsertCount,
												 update_count = UpdateCount,
												 error_count = ErrorCount,
												 disable_count = DisabledCount,
												 skip_count = SkipCount}};
							{error, Reason2} = Error2 -> 
								?DEBUG("~s do_update failed to execute sql ~p. Reason: ~p.", [Name, SqlUpdate, Reason2]),
								ems_odbc_pool:release_connection(Datasource2),
								Error2
						end,
						Result;
					{error, Reason3} = Error3 -> 
						ems_logger:warn("~s do_update failed to get connection. Reason: ~p.", [Name, Reason3]),
						Error3
				end;
			_ -> 
				{ok, State#state{insert_count = 0,
								 error_count = 0,
								 disable_count = 0,
								 skip_count = 0}}
		end
	catch
		_Exception:Reason4 -> 
			ems_logger:error("~s do_update exception. Reason: ~p.", [Name, Reason4]),
			{error, Reason4}
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


-spec do_check_remove_records(list(), #state{}) -> non_neg_integer().
do_check_remove_records([], _) -> 0;
do_check_remove_records(Ids, #state{middleware = Middleware, source_type = SourceType}) ->
	Table = apply(Middleware, get_table, [SourceType]),
	case not is_integer(hd(Ids)) of
		true -> Ids2 = [list_to_integer(R) || R <- Ids]; % os ids estão vindo como string
		false -> Ids2 = Ids
	end,
	F = fun() ->
		  qlc:e(
			 qlc:q([element(2, Rec) || Rec <- mnesia:table(Table)])
		  )
	   end,
	IdsDB = ordsets:from_list(Ids2), 
	IdsMnesia = ordsets:from_list(mnesia:activity(async_dirty, F)),
	IdsDiff = ordsets:subtract(IdsMnesia, IdsDB),
	%io:format("listas IdsDB ~p   IdsMnesia ~p   IdsDiff ~p\n",  [IdsDB, IdsMnesia, IdsDiff]),
	do_remove_records_(IdsDiff, Table),
	length(IdsDiff).


-spec do_remove_records_(list(non_neg_integer()), atom()) -> ok.
do_remove_records_([], _) -> ok;
do_remove_records_([Id|T], Table) ->
	mnesia:dirty_delete(Table, Id),
	do_remove_records_(T, Table).


-spec do_after_load_or_update_checkpoint(#state{}) -> ok.
do_after_load_or_update_checkpoint(#state{middleware = Middleware, source_type = SourceType}) ->
	apply(Middleware, after_load_or_update_checkpoint, [SourceType]).
	
	


