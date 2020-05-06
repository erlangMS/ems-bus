%%******************************************************************** 
%% @title Module ems_data_loader  
%% @version 1.0.0 
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
				sql_load_packet_length,
				sql_update,
				sql_count,
				sql_ids,
				sql_fields,
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
				loading = false,
				allow_clear_table_full_sync = false,
				group,
				wait_count = 0,
				insert_count = 0,
				update_count = 0,
				error_count = 0,
				disable_count = 0,
				skip_count = 0,
				error_db_count = 0,
				log_show_data_loader_activity = false
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
	Result = 6000 - (WaitCount * 100),
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
	Conf = ems_config:getConfig(),
	LastUpdateParamName = erlang:binary_to_atom(iolist_to_binary([Name, <<"_last_update_param_name">>]), utf8),
	LastUpdate = ems_db:get_param(LastUpdateParamName),
	UpdateCheckpoint = maps:get(<<"update_checkpoint">>, Props, ?DATA_LOADER_UPDATE_CHECKPOINT),
	CheckRemoveRecords = ems_util:parse_bool(maps:get(<<"check_remove_records">>, Props, false)),
	CheckRemoveRecordsCheckpoint0 = maps:get(<<"check_remove_records_checkpoint">>, Props, ?DATA_LOADER_UPDATE_CHECKPOINT),
	case CheckRemoveRecordsCheckpoint0 < UpdateCheckpoint of
		true -> CheckRemoveRecordsCheckpoint = UpdateCheckpoint + 5000 + rand:uniform(30000);
		false -> CheckRemoveRecordsCheckpoint = CheckRemoveRecordsCheckpoint0 + rand:uniform(30000)
	end,
	SqlLoad = ems_util:str_trim(binary_to_list(maps:get(<<"sql_load">>, Props, <<>>))),
	SqlLoadPacketLength = maps:get(<<"sql_load_packet_length">>, Props, 4000),
	SqlUpdate = ems_util:str_trim(binary_to_list(maps:get(<<"sql_update">>, Props, <<>>))),
	SqlCount = re:replace(SqlLoad, "select (.+)( from.+)( order by.+)?","select count(1)\\2", [{return,list}]),
	SqlIds = re:replace(SqlLoad, "select ([^,]+),(.+)( from.+)( order by.+)?", "select \\1 \\3", [{return,list}]),
	Fields = maps:get(<<"fields">>, Props, []),
	SqlFields = string:join(ems_util:binlist_to_list(Fields), ","),
	SourceType = binary_to_atom(maps:get(<<"source_type">>, Props, <<"db">>), utf8),
	TimeoutOnError = maps:get(<<"timeout_on_error">>, Props, 120000) + rand:uniform(60000),
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
	%erlang:send_after(60000 * 60, self(), check_sync_full),
	case CheckRemoveRecords andalso CheckRemoveRecordsCheckpoint > 0 of
		true -> erlang:send_after(CheckRemoveRecordsCheckpoint + 90000 + rand:uniform(10000), self(), check_count_records);
		false -> ok
	end,
	LogShowDataLoaderActivity =  ems_util:parse_bool(maps:get(<<"log_show_data_loader_activity">>, Props, Conf#config.log_show_data_loader_activity)),
	State = #state{name = NameStr,
				   datasource = Datasource, 
				   update_checkpoint = UpdateCheckpoint,
				   last_update_param_name = LastUpdateParamName,
				   last_update = LastUpdate,
				   check_remove_records_checkpoint = CheckRemoveRecordsCheckpoint,
				   sql_load = SqlLoad,
				   sql_load_packet_length = SqlLoadPacketLength,
				   sql_update = SqlUpdate,
				   sql_count = SqlCount,
				   sql_ids = SqlIds,
				   sql_fields = SqlFields,
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
				   skip_count = 0,
				   error_db_count = 0,
				   log_show_data_loader_activity = LogShowDataLoaderActivity
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
											wait_count = WaitCount,
											log_show_data_loader_activity = LogShowDataLoaderActivity
										}) ->
		{{_, _, _}, {Hour, _, _}} = calendar:local_time(),
		case (Hour == 5 orelse (Hour >= 8 andalso Hour =< 20 andalso (Hour rem 2 =:= 0))) of
			true ->
				case not Loading andalso ems_data_loader_ctl:permission_to_execute(Name, GroupDataLoader, check_sync_full, WaitCount) of
					true ->
						ems_db:inc_counter(SyncFullCheckpointMetricName),
						ems_logger:info("~s sync full begin now.", [Name], LogShowDataLoaderActivity),
						State2 = State#state{last_update = undefined,
											 allow_clear_table_full_sync = false},  
						case do_check_load_or_update_checkpoint(State2) of
							{ok, State3 = #state{insert_count = InsertCount, update_count = UpdateCount, error_count = ErrorCount, disable_count = DisableCount, skip_count = SkipCount}} ->
								ems_data_loader_ctl:notify_finish_work(Name, check_sync_full, WaitCount, InsertCount, UpdateCount, ErrorCount, DisableCount, SkipCount, undefined),
								ems_logger:info("~s sync full checkpoint successfully", [Name], LogShowDataLoaderActivity),
								ems_util:flush_messages(),
								erlang:send_after(3600000, self(), check_sync_full),
								{noreply, State3#state{wait_count = 0}, UpdateCheckpoint + 180000};  % adiciona 180 segundos para priorizar os demais loaders
							{error, Reason} -> 
								ems_data_loader_ctl:notify_finish_work(Name, check_sync_full, WaitCount, 0, 0, 0, 0, 0, Reason),
								ems_db:inc_counter(ErrorCheckpointMetricName),
								ems_util:flush_messages(),
								erlang:send_after(3600000, self(), check_sync_full),
								ems_logger:error("~s sync full wait ~pms for next checkpoint while has database connection error. Reason: ~p.", [Name, TimeoutOnError, Reason], LogShowDataLoaderActivity),
								{noreply, State#state{wait_count = 0}, TimeoutOnError}
						end;
					false ->
						TimeoutWait = get_timeout_wait(WaitCount),
						ems_logger:warn("~s handle check_sync_full wait ~pms to execute (WaitCount: ~p).", [Name, TimeoutWait, WaitCount], LogShowDataLoaderActivity),
						erlang:send_after(TimeoutWait, self(), check_sync_full),
						{noreply, State#state{wait_count = WaitCount + 1}, UpdateCheckpoint}
				end;
			_ -> 
				erlang:send_after(60000 * 5, self(), check_sync_full),
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
					ems_util:flush_messages(),
					erlang:send_after(CheckRemoveRecordsCheckpoint, self(), check_count_records),
					{noreply, State2#state{wait_count = 0}, UpdateCheckpoint};
				{error, Reason} -> 
					ems_data_loader_ctl:notify_finish_work(Name, check_count_records, WaitCount, 0, 0, 0, 0, 0, Reason),
					ems_db:inc_counter(ErrorCheckpointMetricName),
					ems_util:flush_messages(),
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
			
handle_info(_Msg, State = #state{update_checkpoint = UpdateCheckpoint}) ->
	{noreply, State, UpdateCheckpoint}.
		
terminate(Reason, #state{name = Name}) ->
    ems_logger:info("~s terminate. Reason: ~p.", [Name, Reason]),
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_do_check_load_or_update_checkpoint(State = #state{name = Name,
														 update_checkpoint = UpdateCheckpoint,
														 timeout_on_error = TimeoutOnError,
														 error_checkpoint_metric_name = ErrorCheckpointMetricName,
														 loading = Loading,
														 group = DataLoaderGroup,
														 wait_count = WaitCount,
														 error_db_count = ErrorDBCount,
														 log_show_data_loader_activity = LogShowDataLoaderActivity}) ->
	try
		put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass1),
		case ems_data_loader_ctl:permission_to_execute(Name, DataLoaderGroup, check_load_or_update_checkpoint, WaitCount) of
			true ->
				?DEBUG("~s handle_do_check_load_or_update_checkpoint execute now.", [Name]),
				put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass2),
				case do_check_load_or_update_checkpoint(State) of
					{ok, State2 = #state{insert_count = InsertCount, update_count = UpdateCount, error_count = ErrorCount, disable_count = DisableCount, skip_count = SkipCount}} ->
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass3),
						do_after_load_or_update_checkpoint(State2),
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass4),
						ems_data_loader_ctl:notify_finish_work(Name, check_load_or_update_checkpoint, WaitCount, InsertCount, UpdateCount, ErrorCount, DisableCount, SkipCount, undefined),
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass5),
						ems_util:flush_messages(),
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass6),
						case Loading of
							true -> {noreply, State2#state{wait_count = 0, error_db_count = 0}, UpdateCheckpoint + 90000};
							false -> {noreply, State2#state{wait_count = 0, error_db_count = 0}, UpdateCheckpoint}
						end;
					{error, eodbc_restricted_connection} -> 
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass7),
						ems_data_loader_ctl:notify_finish_work(Name, check_count_records, WaitCount, 0, 0, 0, 0, 0, eodbc_restricted_connection),
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass8),
						case ErrorDBCount > 5 of
							true -> 
								TimeoutOnError2 = TimeoutOnError * 6,
								ems_logger:format_error("~s do_check_load_or_update_checkpoint wait ~pms for next checkpoint while database in backup or restricted connection. ErrorDBCount: ~p. Reason: ~p.", [Name, TimeoutOnError2, ErrorDBCount, eodbc_restricted_connection], LogShowDataLoaderActivity);
							false -> 
								TimeoutOnError2 = TimeoutOnError,
								ems_logger:error("~s do_check_load_or_update_checkpoint wait ~pms for next checkpoint while database in backup or restricted connection. ErrorDBCount: ~p. Reason: ~p.", [Name, TimeoutOnError2, ErrorDBCount, eodbc_restricted_connection], LogShowDataLoaderActivity)
						end,
						ems_util:flush_messages(),
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass9),
						{noreply, State#state{wait_count = 0, error_db_count = ErrorDBCount+1}, TimeoutOnError2};
					{error, Reason} -> 
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass10),
						ems_data_loader_ctl:notify_finish_work(Name, check_count_records, WaitCount, 0, 0, 0, 0, 0, Reason),
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass11),
						ems_db:inc_counter(ErrorCheckpointMetricName),
						ems_util:flush_messages(),
						case ErrorDBCount > 5 of
							true -> 
								TimeoutOnError2 = TimeoutOnError * 3,
								ems_logger:format_error("~s do_check_load_or_update_checkpoint wait ~pms for next checkpoint while has database connection error. ErrorDBCount: ~p. Reason: ~p.", [Name, TimeoutOnError, ErrorDBCount, Reason], LogShowDataLoaderActivity);
							false -> 
								TimeoutOnError2 = TimeoutOnError,
								ems_logger:error("~s do_check_load_or_update_checkpoint wait ~pms for next checkpoint while has database connection error. ErrorDBCount: ~p. Reason: ~p.", [Name, TimeoutOnError, ErrorDBCount, Reason], LogShowDataLoaderActivity)
						end,
						put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass12),
						{noreply, State#state{wait_count = 0, error_db_count = ErrorDBCount+1}, TimeoutOnError2}
				end;
			false ->
				put(handle_do_check_load_or_update_checkpoint_step, handle_do_check_load_or_update_checkpoint_step_pass13),
				TimeoutWait = get_timeout_wait(WaitCount),
				{noreply, State#state{wait_count = WaitCount + 1}, TimeoutWait}
		end
	catch
		_:ReasonException ->
			ems_logger:error("ems_data_loader handle_do_check_load_or_update_checkpoint exception. Step: ~p. Reason: ~p.", [get(handle_do_check_load_or_update_checkpoint_step), ReasonException]),
			{noreply, State, 60000}	% tenta se recuperar para não quebrar o processo
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
										ems_odbc_pool:shutdown_connection(Datasource2),
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
										ems_odbc_pool:shutdown_connection(Datasource2),
										?DEBUG("~s do_check_count_checkpoint exception to execute sql ~p.", [Name, SqlIds]),
										Error3
								end;
							true ->
								ems_odbc_pool:shutdown_connection(Datasource2),
								?DEBUG("~s do_check_count_checkpoint skip remove records.", [Name]),
								{ok, State}
						end;
					Error4 -> 
						ems_odbc_pool:shutdown_connection(Datasource2),
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
												  last_update = LastUpdate,
												  log_show_data_loader_activity = LogShowDataLoaderActivity}) ->
	% garante que os dados serão atualizados mesmo que as datas não estejam sincronizadas
	ems_logger:info("~s begin syncronize data...", [Name], LogShowDataLoaderActivity),
	NextUpdate = ems_util:date_dec_minute(calendar:local_time(), 59), 
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
										 load_checkpoint_metric_name = LoadCheckpointMetricName}) -> 
	try
		case ems_odbc_pool:get_connection(Datasource) of
			{ok, Datasource2} -> 
				Result = do_load_table(CtrlInsert, Conf, State#state{datasource = Datasource2}),
				%% faz shutdown da conexão em vez de voltar ao pool pois consome muita ram durante as cargas de dados completa
				ems_odbc_pool:shutdown_connection(Datasource2), 
				ems_db:inc_counter(LoadCheckpointMetricName),
				Result;
			Error3 -> Error3
		end
	catch
		_Exception:Reason4 -> 
			ems_logger:error("~s do_load exception. Reason: ~p.", [Name, Reason4]),
			{error, Reason4}
	end.

do_load_table(CtrlInsert, Conf, State = #state{name = Name,
											   insert_metric_name = InsertMetricName,
											   error_metric_name = ErrorsMetricName,
											   disable_metric_name = DisabledMetricName,
											   skip_metric_name = SkipMetricName,
											   allow_clear_table_full_sync = AllowClearTableFullSync,
											   log_show_data_loader_activity = LogShowDataLoaderActivity}) -> 
	try
		case AllowClearTableFullSync of
			true ->
				case do_clear_table(State) of
					ok ->
						do_reset_sequence(State),
						case do_load_data_pump(CtrlInsert, Conf, State, 1, 0, 0, 0, 0) of
							{ok, InsertCount, ErrorCount, DisabledCount, SkipCount} ->
								ems_logger:info("~s sync full ~p inserts, ~p disabled, ~p skips, ~p errors.", [Name, InsertCount, DisabledCount, SkipCount, ErrorCount], LogShowDataLoaderActivity),
								ems_db:counter(InsertMetricName, InsertCount),
								ems_db:counter(ErrorsMetricName, ErrorCount),
								ems_db:counter(DisabledMetricName, DisabledCount),
								ems_db:counter(SkipMetricName, SkipCount),
								{ok, State#state{insert_count = InsertCount,
												 error_count = ErrorCount,
												 disable_count = DisabledCount,
												 skip_count = SkipCount}};
							Error -> Error
						end;
					Error ->
						ems_logger:error("~s do_load could not clear table before load data.", [Name], LogShowDataLoaderActivity),
						Error
				end;
			false ->
				case do_load_data_pump(CtrlInsert, Conf, State, 1, 0, 0, 0, 0) of
					{ok, InsertCount, ErrorCount, DisabledCount, SkipCount} ->
						ems_logger:info("~s sync ~p inserts, ~p disabled, ~p skips, ~p errors.", [Name, InsertCount, DisabledCount, SkipCount, ErrorCount], LogShowDataLoaderActivity),
						ems_db:counter(InsertMetricName, InsertCount),
						ems_db:counter(ErrorsMetricName, ErrorCount),
						ems_db:counter(DisabledMetricName, DisabledCount),
						ems_db:counter(SkipMetricName, SkipCount),
						{ok, State#state{insert_count = InsertCount,
										 update_count = 0,
										 error_count = ErrorCount,
										 disable_count = DisabledCount,
										 skip_count = SkipCount}};
					Error -> Error
				end
		end
	catch
		_Exception:Reason4 -> 
			ems_logger:error("~s do_load_query exception. Reason: ~p.", [Name, Reason4]),
			{error, Reason4}
	end.

do_load_data_pump(CtrlInsert, 
				  Conf, 
				  State = #state{datasource = Datasource,
								 name = Name,
								 middleware = Middleware,
								 sql_load = SqlLoad,
								 sql_load_packet_length = SqlLoadPacketLength,
								 sql_fields = SqlFields,
								 fields = Fields,
								 source_type = SourceType,
								 log_show_data_loader_activity = LogShowDataLoaderActivity}, 
				 Offset, InsertCount, ErrorCount, DisabledCount, SkipCount) -> 
	try
		case SqlLoadPacketLength == 0 of
			true -> 
				% Quando SqlLoadPacketLength é 0, o load incremental por pacotes é desligado
				Params = [],
				SqlLoad2 = SqlLoad;
			false ->
				case Datasource#service_datasource.type of
					sqlserver ->
						case Offset > 1 of
							true ->	
								Params = [{sql_integer, [Offset]},
										  {sql_integer, [Offset+SqlLoadPacketLength-1]}
										 ],
								SqlLoad2 = io_lib:format("select ~s from ( select ~s, row_number() over (order by id) AS _RowNumber from ( ~s ) _t_sql ) _t where _t._RowNumber between ? and ?", [SqlFields, SqlFields, SqlLoad]);
							false -> 
								% Quando o offset é 1, usamos select top para obter um pouco mais de performance na primeira query
								Params = [],
								SqlLoad2 = io_lib:format("select top ~p ~s from ( ~s ) _t_sql order by id", [Offset+SqlLoadPacketLength-1, SqlFields, SqlLoad])
						end;
					postgresql ->
						Params = [{sql_integer, [Offset]},
								  {sql_integer, [Offset+SqlLoadPacketLength-1]}
								 ],
						SqlLoad2 = io_lib:format("select ~s from ( select ~s, row_number() over (order by id) AS _RowNumber from ( ~s ) _t_sql ) _t where _t._RowNumber between ? and ?", [SqlFields, SqlFields, SqlLoad]);
					db2 ->
						Params = [{sql_integer, [Offset]},
								  {sql_integer, [Offset+SqlLoadPacketLength-1]}
								 ],
						SqlLoad2 = io_lib:format("select ~s from ( select ~s, row_number() over (order by id) AS RowNumber from ( ~s ) t_sql ) t where t.RowNumber between ? and ?", ["*", "*", SqlLoad])
				end
		end,
		SqlLoad3 = re:replace(SqlLoad2, "\\s+", " ", [global,{return,list}]),
		SqlLoad4 = re:replace(SqlLoad3, "\\s+$", "", [global,{return,list}]),
		case ems_odbc_pool:param_query(Datasource, SqlLoad4, Params) of
			{_, _, []} -> 
				{ok, InsertCount, ErrorCount, DisabledCount, SkipCount};
			{_, _, Records} ->
				case SqlLoadPacketLength == 0 of
					true -> 
						{ok, InsertCount2, _, ErrorCount2, DisabledCount2, SkipCount2} = ems_data_pump:data_pump(Records, list_to_binary(CtrlInsert), Conf, Name, Middleware, insert, 0, 0, 0, 0, 0, SourceType, Fields),
						{ok, InsertCount2, ErrorCount2, DisabledCount2, SkipCount2};
					false ->
						{ok, InsertCount2, _, ErrorCount2, DisabledCount2, SkipCount2} = ems_data_pump:data_pump(Records, list_to_binary(CtrlInsert), Conf, Name, Middleware, insert, 0, 0, 0, 0, 0, SourceType, Fields),
						do_load_data_pump(CtrlInsert, Conf, State, Offset + SqlLoadPacketLength, InsertCount + InsertCount2, ErrorCount + ErrorCount2, DisabledCount + DisabledCount2, SkipCount + SkipCount2)
				end;
			{error, Reason} = Error -> 
				ems_logger:error("~s do_load_data_pump fetch exception. Reason: ~p.", [Name, Reason], LogShowDataLoaderActivity),
				Error
		end
	catch
		_Exception:Reason4 -> 
			ems_logger:error("~s do_load_data_pump exception. Reason: ~p.", [Name, Reason4]),
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
													   source_type = SourceType,
													   log_show_data_loader_activity = LogShowDataLoaderActivity}) -> 
	try
		% do_update is optional
		case SqlUpdate =/= "" of
			true ->
				case ems_odbc_pool:get_connection(Datasource) of
					{ok, Datasource2} -> 
						ems_db:inc_counter(UpdateCheckpointMetricName),
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
								  {sql_timestamp, [DateInitial]},
								  {sql_timestamp, [DateInitial]}],
						Result = case ems_odbc_pool:param_query(Datasource2, SqlUpdate, Params) of
							{_,_,[]} -> 
								ems_odbc_pool:shutdown_connection(Datasource2), 
								ems_db:inc_counter(UpdateMissMetricName),
								ems_logger:info("~s sync 0 inserts, 0 updates, 0 disabled, 0 skips, 0 errors since ~s.", [Name, ems_util:timestamp_str(LastUpdate)], LogShowDataLoaderActivity),
								{ok, State#state{insert_count = 0,
												 error_count = 0,
												 disable_count = 0,
												 skip_count = 0}};
							{_, _, Records} ->
								ems_odbc_pool:shutdown_connection(Datasource2), 
								{ok, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount} = ems_data_pump:data_pump(Records, list_to_binary(CtrlUpdate), Conf, Name, Middleware, update, 0, 0, 0, 0, 0, SourceType, Fields),
								ems_db:counter(InsertMetricName, InsertCount),
								ems_db:counter(UpdateMetricName, UpdateCount),
								ems_db:counter(ErrorsMetricName, ErrorCount),
								ems_db:counter(DisabledMetricName, DisabledCount),
								ems_db:counter(SkipMetricName, SkipCount),
								ems_logger:info("~s sync ~p inserts, ~p updates, ~p disabled, ~p skips, ~p errors since ~s.", [Name, InsertCount, UpdateCount, DisabledCount, SkipCount, ErrorCount, ems_util:timestamp_str(LastUpdate)], LogShowDataLoaderActivity),
								{ok, State#state{insert_count = InsertCount,
												 update_count = UpdateCount,
												 error_count = ErrorCount,
												 disable_count = DisabledCount,
												 skip_count = SkipCount}};
							{error, _Reason2} = Error2 -> 
								ems_odbc_pool:shutdown_connection(Datasource2), 
								Error2
						end,
						Result;
					Error3 -> Error3
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
	
	


