%%********************************************************************
%% @title Module ems_logger
%% @version 1.0.0
%% @doc Module responsible for the logger component.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_logger).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-compile({no_auto_import,[error/2]}).

%% Server API
-export([start/1, stop/0]).

%% Client API
-export([error/1, error/2, error/3,
		 info/1, info/2, info/3, 
		 warn/1, warn/2, warn/3,
		 debug/1, debug/2, debug/3,
		 debug2/1, debug2/2, debug2/3,
		 in_debug/0, mode_debug/1, 
		 sync/0, 
		 log_request/1, 
		 set_level/1, 
		 show_response/1, show_response/2, 
		 show_payload/1, show_payload/2, 
		 show_response_url/2, show_payload_url/2,
		 show_response_url/3, show_payload_url/3,
		 log_file_tail/0, log_file_tail/1, 
		 log_file_head/0, log_file_head/1, log_file_name/0, 
		 format_info/1, format_info/2, format_warn/1, format_warn/2, 
		 format_error/1, format_error/2, format_debug/1, 
		 format_debug/2, format_alert/1, format_alert/2, checkpoint/0
]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).


%  Armazena o estado do ems_logger. 
-record(state, {log_buffer = [],             				% The messages go first to a log_buffer subsequently to the log file        
			    log_log_buffer_screen = [],        			% The messages go first to a log_buffer subsequently to screen
				log_file_checkpoint,      					% timeout archive log checkpoing
				log_file_name,		      					% log file name
				log_file_handle,							% IODevice of file
				log_file_max_size,							% Max file size in KB
				log_level = info,							% log_level of printable messages
				log_show_response = false,					% show response of request
				log_show_response_max_length,				% show response if content length < show_response_max_length
				log_show_payload = false,					% show payload of request
				log_show_payload_max_length,				% show payload if content length < show_response_max_length
				log_show_response_url_list = [],			% show response if url in 
				log_show_payload_url_list = [],				% show payload if url in 
				log_ult_msg,								% last print message
				log_ult_reqhash, 							% last reqhash of print message
				log_file_path,
				log_file_archive_path,
				log_file_sync_log_buffer_time_ref,
				log_file_sync_log_buffer_tela_time_ref
 			   }). 


%%====================================================================
%% Server API
%%====================================================================

start(Service) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Service, []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 
 
%%====================================================================
%% Client API
%%====================================================================
 
error(Msg) -> 
	gen_server:cast(?SERVER, {write_msg, error, Msg}). 

error(Msg, Params) -> 
	gen_server:cast(?SERVER, {write_msg, error, Msg, Params}). 

error(Msg, Params, true) -> error(Msg, Params);
error(_, _, false) -> ok.

warn(Msg) -> 
	gen_server:cast(?SERVER, {write_msg, warn, Msg}). 

warn(Msg, Params) -> 
	gen_server:cast(?SERVER, {write_msg, warn, Msg, Params}). 
	
warn(Msg, Params, true) -> 	warn(Msg, Params);
warn(_, _, false) -> ok.


info(Msg) -> 
	gen_server:cast(?SERVER, {write_msg, info, Msg}).

info(Msg, Params) -> 
	gen_server:cast(?SERVER, {write_msg, info, Msg, Params}). 

info(Msg, Params, true) -> info(Msg, Params);
info(_, _, false) -> ok.


debug(Msg) -> 
	case in_debug() of
		true -> gen_server:cast(?SERVER, {write_msg, debug, Msg});
		_ -> ok
	end.

debug(Msg, Params) -> 
	case in_debug() of
		true -> gen_server:cast(?SERVER, {write_msg, debug, Msg, Params});
		_ -> ok
	end.
	
debug(Msg, Params, true) -> debug(Msg, Params);
debug(_, _, false) ->  ok.

debug2(Msg) -> 
	case in_debug() of
		true -> 
			Msg2 = lists:concat(["\033[1;34mDEBUG ", ems_clock:local_time_str(), "  ", Msg, "\033[0m"]),
			io:format(Msg2);
		_ -> ok
	end.

debug2(Msg, Params) -> 
	case in_debug() of
		true -> 
			Msg2 = lists:concat(["\033[1;34mDEBUG ", ems_clock:local_time_str(), "  ", io_lib:format(Msg, Params), "\033[0m"]),
			io:format(Msg2);
		_ -> ok
	end.

debug2(Msg, Params, true) -> debug2(Msg, Params);
debug2(_, _, false) -> ok.


in_debug() -> ets:lookup(debug_ets, debug) =:= [{debug, true}].

mode_debug(true)  -> 
	info("ems_logger debug mode enabled."),
	ets:insert(debug_ets, {debug, true});
mode_debug(false) -> 
	info("ems_logger debug mode disabled."),
	ets:insert(debug_ets, {debug, false}).

sync() ->
	info("ems_logger sync log_buffer."),
	gen_server:cast(?SERVER, sync_log_buffer). 

log_request(Request) -> 
	gen_server:cast(?SERVER, {log_request, Request}).

set_level(Level) -> 
	info("ems_logger set log_level ~p.", [Level]),
	gen_server:cast(?SERVER, {set_level, Level}). 

show_response(true) -> 
	info("ems_logger set show response."),
	gen_server:cast(?SERVER, {show_response, true, ?LOG_SHOW_RESPONSE_MAX_LENGTH});
show_response(_) -> 
	info("ems_logger unset show response."),
	gen_server:cast(?SERVER, {show_response, false, ?LOG_SHOW_RESPONSE_MAX_LENGTH}). 

show_response(true, MaxLength) -> 
	info("ems_logger set show response."),
	gen_server:cast(?SERVER, {show_response, true, MaxLength});
show_response(_, MaxLength) -> 
	info("ems_logger unset show response."),
	gen_server:cast(?SERVER, {show_response, false, MaxLength}). 

show_payload(true) -> 
	info("ems_logger set show payload."),
	gen_server:cast(?SERVER, {show_payload, true, ?LOG_SHOW_PAYLOAD_MAX_LENGTH});
show_payload(_) -> 
	info("ems_logger unset show payload."),
	gen_server:cast(?SERVER, {show_payload, false, ?LOG_SHOW_PAYLOAD_MAX_LENGTH}). 

show_payload(true, MaxLength) -> 
	info("ems_logger set show payload."),
	gen_server:cast(?SERVER, {show_payload, true, MaxLength});
show_payload(_, MaxLength) -> 
	info("ems_logger unset show payload."),
	gen_server:cast(?SERVER, {show_payload, false, MaxLength}). 


show_response_url(true, Url) -> 
	info("ems_logger set show response."),
	gen_server:cast(?SERVER, {show_response, true, ?LOG_SHOW_PAYLOAD_MAX_LENGTH, Url});
show_response_url(_, Url) -> 
	info("ems_logger unset show response."),
	gen_server:cast(?SERVER, {show_response, false, ?LOG_SHOW_PAYLOAD_MAX_LENGTH, Url}). 

show_payload_url(true, Url) -> 
	info("ems_logger set show payload."),
	gen_server:cast(?SERVER, {show_payload, true, ?LOG_SHOW_PAYLOAD_MAX_LENGTH, Url});
show_payload_url(_, Url) -> 
	info("ems_logger unset show payload."),
	gen_server:cast(?SERVER, {show_payload, false, ?LOG_SHOW_PAYLOAD_MAX_LENGTH, Url}). 

show_response_url(true, MaxLength, Url) -> 
	info("ems_logger set show response."),
	gen_server:cast(?SERVER, {show_response, true, MaxLength, Url});
show_response_url(_, MaxLength, Url) -> 
	info("ems_logger unset show response."),
	gen_server:cast(?SERVER, {show_response, false, MaxLength, Url}). 

show_payload_url(true, MaxLength, Url) -> 
	info("ems_logger set show payload."),
	gen_server:cast(?SERVER, {show_payload, true, MaxLength, Url});
show_payload_url(_, MaxLength, Url) -> 
	info("ems_logger unset show payload."),
	gen_server:cast(?SERVER, {show_payload, false, MaxLength, Url}). 

log_file_head() ->
	gen_server:call(?SERVER, {log_file_head, 2000}). 		

log_file_head(N) ->
	gen_server:call(?SERVER, {log_file_head, N}). 		

log_file_tail() ->
	gen_server:call(?SERVER, {log_file_tail, 2000}). 		

log_file_tail(N) ->
	gen_server:call(?SERVER, {log_file_tail, N}). 		

log_file_name() ->
	gen_server:call(?SERVER, log_file_name). 		
	
checkpoint() -> 
	format_info("ems_logger archive log file checkpoint."),
	?SERVER ! checkpoint_archive_log.


% write direct messages to console
format_info(Message) when is_list(Message) ->	
	format_info(list_to_binary(Message));
format_info(Message) ->	
	Message2 = iolist_to_binary([?INFO_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message, <<"\n">>]),
	io:format(Message2).

format_info(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?INFO_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message2, <<"\n">>]),
	io:format(Message3).

format_warn(Message) when is_list(Message) ->	
	format_warn(list_to_binary(Message));
format_warn(Message) ->	
	Message2 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:format(Message2).

format_warn(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:format(Message3).

format_error(Message) when is_list(Message) ->	
	format_error(list_to_binary(Message));
format_error(Message) ->	
	Message2 = iolist_to_binary([?ERROR_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:format(Message2).																							

format_error(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?ERROR_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:format(Message3).

format_debug(Message) when is_list(Message) ->	
	format_debug(list_to_binary(Message));
format_debug(Message) ->	
	Message2 = iolist_to_binary([?DEBUG_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?DEBUG_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:format(Message2).

format_debug(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?DEBUG_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?DEBUG_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:format(Message3).

format_alert(Message) when is_list(Message) ->	
	format_alert(list_to_binary(Message));
format_alert(Message) ->	
	Message2 = iolist_to_binary([?ALERT_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message, <<"\n">>]),
	io:format(Message2).

format_alert(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?ALERT_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message2, <<"\n">>]),
	io:format(Message3).





%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(_Service) ->
	Conf = ems_config:getConfig(),
	mode_debug(Conf#config.ems_debug),
	State = #state{log_file_checkpoint = Conf#config.log_file_checkpoint,
				   log_file_max_size = Conf#config.log_file_max_size,
		 		   log_show_response = Conf#config.log_show_response,
				   log_show_payload = Conf#config.log_show_payload,
				   log_show_response_max_length = Conf#config.log_show_response_max_length,
 				   log_show_payload_max_length = Conf#config.log_show_payload_max_length,
 				   log_file_name = undefined,
 				   log_file_handle = undefined,
 				   log_file_path = Conf#config.log_file_path,
 				   log_file_archive_path = Conf#config.log_file_archive_path},
	State2 = checkpoint_arquive_log(State, false),
	erlang:send_after(?LOG_ARCHIVE_CHECKPOINT, self(), checkpoint_archive_log),
    {ok, State2}.
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast({write_msg, Tipo, Msg}, State) ->
	NewState = write_msg(Tipo, Msg, State),
	{noreply, NewState};

handle_cast({write_msg, Tipo, Msg, Params}, State) ->
	NewState = write_msg(Tipo, Msg, Params, State),
	{noreply, NewState};

handle_cast({log_request, Request}, State) ->
	NewState = do_log_request(Request, State),
	{noreply, NewState};

handle_cast({set_level, Level}, State) ->
	{noreply, State#state{log_level = Level}};

handle_cast({show_response, Value, MaxLength}, State) ->
	{noreply, State#state{log_show_response = Value,
						  log_show_response_max_length = MaxLength,
						  log_show_response_url_list = case Value of
															true -> State#state.log_show_response_url_list;
															_ -> []
													   end}};

handle_cast({show_payload, Value, MaxLength}, State) ->
	{noreply, State#state{log_show_payload = Value,
						  log_show_payload_max_length = MaxLength,
						  log_show_payload_url_list = case Value of
															true -> State#state.log_show_payload_url_list;
															_ -> []
													   end}};

handle_cast({show_response, Value, MaxLength, Url}, State) ->
	{noreply, State#state{log_show_response = Value,
						  log_show_response_max_length = MaxLength,
						  log_show_response_url_list = case Value of
															true -> [Url|State#state.log_show_response_url_list];
															_ -> lists:delete(Url, State#state.log_show_response_url_list)
													   end}};

handle_cast({show_payload, Value, MaxLength, Url}, State) ->
	{noreply, State#state{log_show_payload = Value,
						  log_show_payload_max_length = MaxLength,
						  log_show_payload_url_list = case Value of
														   true -> [Url|State#state.log_show_payload_url_list];
														   _ -> lists:delete(Url, State#state.log_show_payload_url_list)
													  end}};

handle_cast(sync_log_buffer, State) ->
	State2 = sync_log_buffer_screen(State),
	State3 = sync_log_buffer(State2),
	{noreply, State3}.

handle_call({write_msg, Tipo, Msg}, _From, State) ->
	NewState = write_msg(Tipo, Msg, State),
	{reply, ok, NewState};

handle_call({write_msg, Tipo, Msg, Params}, _From, State) ->
	NewState = write_msg(Tipo, Msg, Params, State),
	{reply, ok, NewState};

handle_call(sync_log_buffer, _From, State) ->
	NewState = sync_log_buffer(State),
	{reply, ok, NewState};

handle_call(log_file_name, _From, State = #state{log_file_name = FilenameLog}) ->
	{reply, FilenameLog, State};

handle_call({log_file_head, N}, _From, State) ->
	Result = log_file_head(State, N),
	{reply, Result, State};

handle_call({log_file_tail, N}, _From, State) ->
	Result = log_file_tail(State, N),
	{reply, Result, State}.

handle_info(checkpoint_tela, State) ->
   NewState = sync_log_buffer_screen(State),
   {noreply, NewState#state{log_file_sync_log_buffer_tela_time_ref = undefined, log_ult_msg = undefined}};

handle_info(checkpoint, State) ->
   NewState = sync_log_buffer(State),
   {noreply, NewState#state{log_file_sync_log_buffer_time_ref = undefined, log_ult_msg = undefined}};

handle_info(checkpoint_archive_log, State) ->
	Reply = checkpoint_arquive_log(State, false),
	erlang:send_after(?LOG_ARCHIVE_CHECKPOINT, self(), checkpoint_archive_log),
	{noreply, Reply}.

terminate(_Reason, #state{log_file_handle = undefined}) ->
    ok;

terminate(_Reason, #state{log_file_handle = IODevice}) ->
    file:close(IODevice),
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    
    
%%====================================================================
%% Internal functions
%%====================================================================

-spec checkpoint_arquive_log(#state{}, boolean()) -> #state{} | {error, atom()}.
checkpoint_arquive_log(State = #state{log_file_handle = CurrentIODevice, 
									  log_file_name = CurrentLogFilename,
									  log_file_archive_path = LogFileArchivePath}, Immediate) ->
	try
		% Precisamos ver se o arquivo atual ainda existe para arquivar
		case ems_util:file_exists(CurrentLogFilename) of
			true -> 
				CanArchive = true;
			false -> 
				% Vamos fechar o handle do arquivo atual já que o arquivo não existe
				case CurrentIODevice =/= undefined of
					true -> 
						ems_logger:warn("ems_logger close IODevice of inexistent log file \033[01;34m~p\033[0m.", [CurrentLogFilename]),
						file:close(CurrentIODevice);
					false -> ok
				end,
				CanArchive = false
		end,
		
		case CanArchive of
			true ->
				FileSize = filelib:file_size(CurrentLogFilename),
				ems_logger:info("ems_logger starting archive of current log file \033[01;34m~p\033[0m with size: \033[01;34m~p\033[0m bytes.", [CurrentLogFilename, FileSize]),
				case FileSize > 0 of
					true ->
						% Primeira vamos verificar se a pasta onde será arquivado pode ser criada ou já existe
						case ems_util:ensure_dir_writable(LogFileArchivePath) of
							ok -> 
								MakeDir = true;
							{error, ReasonMakeDir} -> 
								MakeDir = false,
								ems_logger:error("ems_logger archive log file failed on create archive path \033[01;34m~p\033[0m. Reason: ~p.", [LogFileArchivePath, ReasonMakeDir])
						end,
						
						case MakeDir of
							true ->
								% Cria um nome de arquivo para arquivamento
								{{Ano,Mes,Dia},{Hora,Min,_}} = calendar:local_time(),
								MesAbrev = ems_util:mes_abreviado(Mes),
								ArchiveLogFilename = lists:flatten(io_lib:format("~s/~p/~s/~s_~s_~2..0w~2..0w~4..0w_~2..0w~2..0w.log", [LogFileArchivePath, Ano, MesAbrev, "server", MesAbrev, Dia, Mes, Ano, Hora, Min])),

								% Vamos ver se consegue criar os subdiretórios da pasta de arquivamento
								case ems_util:ensure_dir_writable(filename:dirname(ArchiveLogFilename)) of
									ok -> 
										MakeSubDir = true;
									{error, ReasonMakeSubDir} -> 
										ems_logger:error("ems_logger archive current log file failed on create archive path \033[01;34m~p\033[0m. Reason: ~p.", [LogFileArchivePath, ReasonMakeSubDir]),
										MakeSubDir = false
								end,

								case MakeSubDir of
									true ->
										case file:copy(CurrentLogFilename, ArchiveLogFilename) of
											{ok, _BytesCopied} ->
												ems_logger:info("ems_logger close current log file \033[01;34m~p\033[0m.", [CurrentLogFilename]),
												file:close(CurrentIODevice),
												file:delete(CurrentLogFilename),
												case Immediate of
													true -> 
														ems_logger:info("ems_logger immediate archive current log file to \033[01;34m~p\033[0m.", [ArchiveLogFilename]);
													false -> 
														ems_logger:info("ems_logger archive current log file to \033[01;34m~p\033[0m.", [ArchiveLogFilename])
												end,
												State2 = create_new_logfile(State);
											{error, Reason2} ->
												State2 = State#state{log_file_name = undefined,
																	 log_file_handle = undefined},
												ems_logger:error("ems_logger archive current log file failed on rename file \033[01;34m~p\033[0m to \033[01;34m~p\033[0m. Reason: ~p.", [CurrentLogFilename, ArchiveLogFilename, Reason2])
										end;
									false ->
										State2 = State#state{log_file_name = undefined,
															 log_file_handle = undefined}
								end;
							false ->
								ems_logger:error("ems_logger archive current log file failed to archive."),
								State2 = State#state{log_file_name = undefined,
													 log_file_handle = undefined}
						end;
					false ->
						ems_logger:info("ems_logger archive current log skip, there's nothing to archive now."),
						State2 = State
				end;
			false -> 
				% Como o arquivo não existe, apenas cria novo arquivo de log
				State2 = create_new_logfile(State)
		end,
		State2
	catch
		_:Reason3 ->
			io:format("checkpoint_arquive_log12\n"),
			ems_db:inc_counter(ems_logger_archive_log_error),
			ems_logger:error("ems_logger archive log file checkpoint exception. Reason: ~p.", [Reason3]),
			State#state{log_file_name = undefined,
						log_file_handle = undefined}
	end.


   
create_new_logfile(State = #state{log_file_path = LogFilePath}) -> 
	file:make_dir(LogFilePath),
	LogFilename = filename:join([LogFilePath, "server.log"]),
	%format_info("ems_logger create_new_logfile \033[01;34m~p\033[0m.", [LogFilename]),
	case filelib:is_dir(LogFilePath) andalso ems_util:path_writable(LogFilePath) of
		true ->
			case file:open(LogFilename, [append]) of
				{ok, IODevice} -> 
					ems_logger:info("ems_logger new log file \033[01;34m~p\033[0m created.", [LogFilename]),
					State#state{log_file_name = LogFilename, 
								log_file_handle = IODevice};
				{error, enospc} ->
					ems_db:inc_counter(ems_logger_enospc),
					ems_logger:error("ems_logger create_new_logfile does not have disk storage space to write to the log files."),
					State#state{log_file_name = undefined, 
								log_file_handle = undefined};
				{error, Reason} -> 
					ems_db:inc_counter(ems_logger_create_file_error),
					ems_logger:error("ems_logger create_new_logfile failed to open log file \033[01;34m~p\033[0m to write. Reason: ~p.", [LogFilename, Reason]),
					State#state{log_file_name = undefined, 
								log_file_handle = undefined}
			end;
		false -> 
			ems_db:inc_counter(ems_logger_create_path_failed),
			format_error("ems_logger create_new_logfile failed to create log file \033[01;34m~p\033[0m.", [LogFilename]),
			State#state{log_file_name = undefined, 
						log_file_handle = undefined}
	end.

log_file_head(#state{log_file_name = LogFilename}, N) ->
	case ems_util:head_file(LogFilename, N) of
		{ok, List} -> {ok, List};
		{error, Reason} = Error -> 
			ems_logger:error("ems_logger log_file_head failed to open log file for read. Reason: ~p.", [Reason]),
			Error
	end.

log_file_tail(#state{log_file_name = LogFilename}, N) ->
	case ems_util:tail_file(LogFilename, N) of
		{ok, List} -> {ok, List};
		{error, Reason} = Error -> 
			ems_logger:error("ems_logger log_file_tail failed to open log file for read. Reason: ~p.", [Reason]),
			Error
	end.


write_msg(Tipo, Msg, State = #state{log_level = Level, 
									log_ult_msg = UltMsg, 
									log_file_checkpoint = LogFileCheckpoint,
									log_file_sync_log_buffer_time_ref = CurrentSyncLogBufferTimeRef,
									log_file_sync_log_buffer_tela_time_ref = CurrentSyncLogBufferTelaTimeRef})  ->
	%% discart overflow duplicated messages
	case UltMsg == undefined orelse UltMsg =/= Msg of
		true ->
			case Tipo of
				info  -> 
					Msg1 = iolist_to_binary([?INFO_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, Msg, <<"\n">>]);
				error -> 
					Msg1 = iolist_to_binary([?ERROR_MESSAGE, ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Msg, ?WHITE_BRK_COLOR]);
				warn  -> 
					Msg1 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Msg, ?WHITE_BRK_COLOR]);
				debug -> 
					Msg1 = iolist_to_binary([?DEBUG_MESSAGE, ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, ?DEBUG_COLOR, Msg, ?WHITE_BRK_COLOR])
			end,
			case (Level == error andalso Tipo /= error) andalso (Tipo /= debug) of
				true ->
					case length(State#state.log_buffer) >= 120 of
						true -> 
							State2 = sync_log_buffer_screen(State),
							case CurrentSyncLogBufferTelaTimeRef of
								undefined -> SyncLogBufferTelaTimeRef = erlang:send_after(500, self(), checkpoint_tela);
								_ -> SyncLogBufferTelaTimeRef = CurrentSyncLogBufferTelaTimeRef
							end,
							State2#state{log_buffer = [Msg1], 
										 log_ult_msg = undefined,
										 log_file_sync_log_buffer_tela_time_ref = SyncLogBufferTelaTimeRef};
						false -> 
							case CurrentSyncLogBufferTelaTimeRef of
								undefined -> SyncLogBufferTelaTimeRef = erlang:send_after(500, self(), checkpoint_tela);
								_ -> SyncLogBufferTelaTimeRef = CurrentSyncLogBufferTelaTimeRef
							end,
							State#state{log_buffer = [Msg1|State#state.log_buffer], 
									    log_file_sync_log_buffer_tela_time_ref = SyncLogBufferTelaTimeRef}
					end;
				false ->
					case length(State#state.log_buffer) >= 80 of
						true -> 
							State2 = sync_log_buffer_screen(State),
							State3 = sync_log_buffer(State2),
							case CurrentSyncLogBufferTelaTimeRef of
								undefined -> SyncLogBufferTelaTimeRef = erlang:send_after(500, self(), checkpoint_tela);
								_ -> SyncLogBufferTelaTimeRef = CurrentSyncLogBufferTelaTimeRef
							end,
							case CurrentSyncLogBufferTimeRef of
								undefined -> SyncLogBufferTimeRef = erlang:send_after(LogFileCheckpoint, self(), checkpoint);
								_ -> SyncLogBufferTimeRef = CurrentSyncLogBufferTimeRef
							end,
							State3#state{log_buffer = [Msg1], 
										 log_log_buffer_screen = [Msg1],
										 log_ult_msg = undefined,
										 log_file_sync_log_buffer_time_ref = SyncLogBufferTimeRef,
										 log_file_sync_log_buffer_tela_time_ref = SyncLogBufferTelaTimeRef};
						false ->
							case CurrentSyncLogBufferTelaTimeRef of
								undefined -> 
									SyncLogBufferTelaTimeRef = erlang:send_after(500, self(), checkpoint_tela);
								_ -> 
									SyncLogBufferTelaTimeRef = CurrentSyncLogBufferTelaTimeRef
							end,
							case CurrentSyncLogBufferTimeRef of
								undefined -> SyncLogBufferTimeRef = erlang:send_after(LogFileCheckpoint, self(), checkpoint);
								_ -> SyncLogBufferTimeRef = CurrentSyncLogBufferTimeRef
							end,
							State#state{log_buffer = [Msg1|State#state.log_buffer], 
										log_log_buffer_screen = [Msg1|State#state.log_log_buffer_screen], 
										log_ult_msg = Msg,
										log_file_sync_log_buffer_time_ref = SyncLogBufferTimeRef,
										log_file_sync_log_buffer_tela_time_ref = SyncLogBufferTelaTimeRef}
					end
			end;
		false -> 
			State
	end.
	
write_msg(Tipo, Msg, Params, State) ->
	Msg1 = io_lib:format(Msg, Params),
	write_msg(Tipo, Msg1, State).
	
	
sync_log_buffer_screen(State = #state{log_log_buffer_screen = [], log_ult_msg = undefined, log_ult_reqhash = undefined}) -> State;
sync_log_buffer_screen(State) ->
	MsgList = lists:reverse(State#state.log_log_buffer_screen),
	sync_log_buffer_screen_(MsgList),
	State#state{log_log_buffer_screen = [], log_ult_msg = undefined, log_ult_reqhash = undefined}.

sync_log_buffer_screen_([]) -> ok;
sync_log_buffer_screen_([H|T]) ->
	try
		io:format(H),
		sync_log_buffer_screen_(T)
	catch
		_:_ -> 
			% se ocorrer algum erro, imprime as demais mensagens
			sync_log_buffer_screen_(T)
	end.

sync_log_buffer(State = #state{log_buffer = []}) -> State;
sync_log_buffer(State = #state{log_buffer = Buffer,
							   log_file_name = CurrentLogFilename,
							   log_file_max_size = LogFileMaxSize,
							   log_file_handle = CurrentLogFileHandle}) ->
	try
		case CurrentLogFileHandle == undefined of
			true -> 
				State2 = checkpoint_arquive_log(State, true);
			false ->
				FileSize = filelib:file_size(CurrentLogFilename),
				case FileSize > LogFileMaxSize of 	% check limit log file max size
					true -> 
						ems_db:inc_counter(ems_logger_sync_log_buffer_file_size_exceeded),
						ems_logger:info("ems_logger is writing to a log file that has already exceeded the allowed limit."),
						State2 = checkpoint_arquive_log(State, true);
					false ->
						case filelib:is_regular(CurrentLogFilename) of % Check file deleted
							false ->
								ems_db:inc_counter(ems_logger_sync_buffer_file_deleted),
								ems_logger:error("ems_logger is writing to a log file deleted."),
								State2 = checkpoint_arquive_log(State, true);
							true ->
								State2 = State#state{log_buffer = [], log_ult_msg = undefined, log_ult_reqhash = undefined}
						end
				end
		end,
		Msg = lists:reverse(Buffer),
		case file:write(State2#state.log_file_handle, Msg) of
			ok -> 
				ok;
			{error, enospc} -> 
				ems_db:inc_counter(ems_logger_sync_log_buffer_enospc),
				ems_logger:error("ems_logger does not have disk storage space to write to the log files.");
			{error, ebadf} ->
				ems_db:inc_counter(ems_logger_sync_log_buffer_ebadf),
				sync_log_buffer(State#state{log_file_name = undefined,
											log_file_handle = undefined});
			{error, Reason} ->
				ems_db:inc_counter(ems_logger_sync_log_buffer_error),
				ems_logger:error("ems_logger was unable to unload the log log_buffer cache. Reason: ~p.", [Reason]);
			Error ->
				ems_db:inc_counter(ems_logger_sync_log_buffer_error),
				ems_logger:error("ems_logger was unable to unload the log log_buffer cache. Reason: ~p.", [Error])
		end,
		State2
	catch
		_:Reason2 ->
			ems_db:inc_counter(ems_logger_sync_buffer_failed),
			ems_logger:error("ems_logger sync_log_buffer exception. Reason: ~p.", [Reason2]),
			State#state{log_buffer = []}
	end.

	
do_log_request(Request = #request{rid = RID,
								  req_hash = ReqHash,
								  type = Type,
								  uri = Uri,
								  url = Url,
								  url_masked = UrlMasked,
								  host = Host,
								  version = Version,
								  content_type_in = ContentTypeIn,
								  content_type_out = ContentTypeOut,
								  content_length = ContentLength,
								  accept = Accept,
								  ip_bin = IpBin,
								  payload = Payload,
								  service = Service,
								  params_url = Params,
								  querystring_map = Query,
								  code = Code,
								  reason = Reason,
								  result_cache = ResultCache,
								  result_cache_rid = ResultCacheRid,
								  response_data = ResponseData,
								  authorization = Authorization,
							      cache_control = CacheControl,
								  etag = Etag,
								  if_modified_since = IfModifiedSince,
								  if_none_match = IfNoneMatch,
								  node_exec = Node,
								  referer = Referer,
								  user_agent = UserAgent,
								  user_agent_version = UserAgentVersion,
								  filename = Filename,
								  client = Client,
								  user = User,
								  scope = Scope,
								  response_header = ResponseHeader,
								  oauth2_grant_type = GrantType,
								  oauth2_access_token = AccessToken,
								  oauth2_refresh_token = RefreshToken,
								  status_text = StatusText
			  }, 
			  State = #state{log_show_response_max_length = ShowResponseMaxLength, 
							 log_show_payload_max_length = ShowPayloadMaxLength, 
							 log_ult_reqhash = UltReqHash,
							 log_show_response_url_list = ShowResponseUrlList,					
							 log_show_payload_url_list = ShowPayloadUrlList}) ->
	try
		case UltReqHash == undefined orelse UltReqHash =/= ReqHash of
			true ->
				ems_user:add_history(Request),
				case Service of
					undefined -> 
						ServiceService = <<>>,
						ResultCacheService = 0,
						AuthorizationService = public,
						ShowResponseService = false,
						ShowPayloadService = false;
					_ ->
						ServiceService = Service#service.service,
						ResultCacheService = Service#service.result_cache,
						AuthorizationService = Service#service.authorization,
						ShowResponseService = Service#service.log_show_response,
						ShowPayloadService = Service#service.log_show_payload
				end,
				TextData = 
					[
					   ?BLUE_COLOR, Type, ?WHITE_SPACE_COLOR, Uri, <<" ">>, atom_to_binary(Version, utf8), <<" ">>,
					   ?TAB_GREEN_COLOR, <<"RID">>, ?WHITE_PARAM_COLOR, integer_to_binary(RID), 
					   <<"  (">>, ?GREEN_COLOR, <<"ReqHash">>, ?WHITE_PARAM_COLOR, integer_to_binary(ReqHash), <<")">>, 
					   case UrlMasked of
							true -> [?TAB_GREEN_COLOR, <<"UrlMasked">>, ?WHITE_PARAM_COLOR, Url];
							false -> <<>>
					   end,
					   ?TAB_GREEN_COLOR, <<"Accept">>, ?WHITE_PARAM_COLOR, Accept,
					   ?TAB_GREEN_COLOR, <<"Content-Type in">>, ?WHITE_PARAM_COLOR, ContentTypeIn, ?SPACE_GREEN_COLOR, <<"out">>, ?WHITE_PARAM_COLOR, ContentTypeOut,
					   ?TAB_GREEN_COLOR, <<"Host">>, ?WHITE_PARAM_COLOR, Host, ?SPACE_GREEN_COLOR, <<"Peer">>, ?WHITE_PARAM_COLOR, IpBin, 
					   ?SPACE_GREEN_COLOR, <<"Referer">>, ?WHITE_PARAM_COLOR, 
												case Referer of
													undefined -> <<>>;
													_ -> Referer
												end,
						?TAB_GREEN_COLOR, <<"User-Agent">>, ?WHITE_PARAM_COLOR, ems_util:user_agent_atom_to_binary(UserAgent), ?SPACE_GREEN_COLOR, <<"Version">>, ?WHITE_PARAM_COLOR, UserAgentVersion,	
						?TAB_GREEN_COLOR, <<"Service">>, ?WHITE_PARAM_COLOR, ServiceService,
						?TAB_GREEN_COLOR, <<"Params">>, ?WHITE_PARAM_COLOR, list_to_binary(io_lib:format("~p", [Params])), 
						?TAB_GREEN_COLOR, <<"Query">>, ?WHITE_PARAM_COLOR, list_to_binary(io_lib:format("~p", [Query])), 
						case (Reason =/= ok orelse 
							   ShowPayloadService orelse 
							   (ShowPayloadUrlList =/= [] andalso lists:member(Url, ShowPayloadUrlList))
							  ) andalso ContentLength > 0 of
							true ->
							   case ContentLength =< ShowPayloadMaxLength of
									true ->
									     Payload2 = case is_binary(Payload) of
														true -> Payload;
														false -> iolist_to_binary(io_lib:format("~p",[Payload]))
										  		    end,
									     [?TAB_GREEN_COLOR, <<"Payload">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLength), 
									      <<" bytes ">>, ?GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, Payload2, ?WHITE_COLOR,
											 case Reason =/= ok of
												true -> ?RED_COLOR;
												false -> <<>>
											 end]; 
									false -> [?TAB_GREEN_COLOR, <<"Payload">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLength), <<" bytes">>, ?SPACE_GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, <<"large content">>]
								end;
							false -> <<>>
						end,
						case (Reason =/= ok orelse 
							   ShowResponseService orelse
							   (ShowResponseUrlList =/= [] andalso lists:member(Url, ShowResponseUrlList))
							  ) of
							true -> 
								 ResponseData2 = case is_binary(ResponseData) of
													true -> ResponseData;
													false -> iolist_to_binary(io_lib:format("~p",[ResponseData]))
												 end,
								 ContentLengthResponse = byte_size(ResponseData2),
							     case ContentLengthResponse > 0 of
									true ->
										case ContentLengthResponse =< ShowResponseMaxLength of
											true -> [?TAB_GREEN_COLOR, <<"Response">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLengthResponse), 
													 <<" bytes  ">>, ?GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, ResponseData2, ?WHITE_COLOR,
													 case Reason =/= ok of
														true -> ?RED_COLOR;
														false -> <<>>
													 end]; 
											false -> [?TAB_GREEN_COLOR, <<"Response">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLengthResponse), <<" bytes  ">>, ?GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, <<"Large content">>]
										end;
									false -> <<>>
								end;
							 false -> <<>>
						end,
					   case ResultCacheService > 0 of
							true ->
							   ResultCacheSec = trunc(ResultCacheService / 1000),
							   case ResultCacheSec > 0 of 
									true  -> ResultCacheMin = trunc(ResultCacheSec / 60);
									false -> ResultCacheMin = 0
							   end,
							   case ResultCacheMin > 0 of
									true -> 
									   case ResultCache of 
											true ->  [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheMin), <<"min)  ">>, ?WARN_COLOR, <<" <<RID: ">>, integer_to_binary(ResultCacheRid), <<">>">>, ?WHITE_COLOR];
											false -> [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheMin), <<"min)">>] 
										end;
									false ->
									   case ResultCacheSec > 0 of
											true -> 
											   case ResultCache of 
													true ->  [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheSec), <<"sec)  ">>, ?WARN_COLOR, <<" <<RID: ">>, integer_to_binary(ResultCacheRid), <<">>">>, ?WHITE_COLOR];
													false -> [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheSec), <<"sec)">>] 
												end;
											false ->
											   case ResultCache of 
													true ->  [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms ">>, ?WARN_COLOR, <<" <<RID: ">>, integer_to_binary(ResultCacheRid), <<">>">>, ?WHITE_COLOR];
													false -> [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms">>]
												end
										end
								end;
							false -> <<>>
						end,
					    ?TAB_GREEN_COLOR, <<"Cache-Control In">>, ?WHITE_PARAM_COLOR, CacheControl,
						?SPACE_GREEN_COLOR, <<"ETag">>, ?WHITE_PARAM_COLOR, case Etag of
											undefined -> <<>>;
											_ -> Etag
										end,
						?TAB_GREEN_COLOR, <<"If-Modified-Since">>, ?WHITE_PARAM_COLOR, case IfModifiedSince of
															undefined -> <<>>;
															_ -> IfModifiedSince
												   end,
					   ?SPACE_GREEN_COLOR, <<"If-None-Match">>, ?WHITE_PARAM_COLOR, case IfNoneMatch of
													undefined -> <<>>;
													_ -> IfNoneMatch
										   end,
					   ?TAB_GREEN_COLOR, <<"Authorization type">>, ?WHITE_PARAM_COLOR, case AuthorizationService of
															basic -> 
																case Authorization of
																	<<>> -> <<"basic, oauth2">>;
																	_ -> <<"oauth2">>
																end;
															oauth2 -> <<"oauth2">>;
															_ -> <<"public">>
													   end,
					   case Authorization of
							<<>> -> <<>>;
							_ -> [?WARN_COLOR, <<" <<">>, Authorization, <<">>">>, ?WHITE_COLOR]
					   end,
					   case GrantType of
									undefined -> <<>>;
									_ -> [?TAB_GREEN_COLOR, <<"OAuth2">>, <<" ">>, ?GREEN_COLOR, <<"grant-type">>, ?WHITE_PARAM_COLOR, GrantType]
					   end,
					   case AccessToken of
							undefined -> <<>>;
							_ ->  [?SPACE_GREEN_COLOR, <<"token">>, ?WHITE_PARAM_COLOR, AccessToken]
					   end,
					   case RefreshToken of
							undefined -> <<>>;
							_ ->  [?SPACE_GREEN_COLOR, <<"refresh token">>, ?WHITE_PARAM_COLOR, RefreshToken]
					   end,
					   case Scope of
							undefined -> <<>>;
							_ -> [?SPACE_GREEN_COLOR, <<"scope">>, ?WHITE_PARAM_COLOR, Scope]
					   end,
					  ?TAB_GREEN_COLOR, <<"Client">>, ?WHITE_PARAM_COLOR, 
									  case Client of
											public -> <<"public">>;
											undefined -> <<>>;
											_ -> [integer_to_binary(Client#client.id), <<" ">>, Client#client.name]
									   end,
					   ?SPACE_GREEN_COLOR, <<"User">>, ?WHITE_PARAM_COLOR, 
										case User of
											public -> <<"public">>;
											undefined -> <<>>;
											_ ->  [integer_to_binary(User#user.id), <<" ">>,  User#user.login]
										 end,
					   ?TAB_GREEN_COLOR, <<"Node">>, ?WHITE_PARAM_COLOR, 
										case Node of
											undefined -> <<>>;
											_ -> Node
										 end,
					   case Filename of
							undefined -> <<>>;
							_ -> [?TAB_GREEN_COLOR, <<"Filename">>, ?WHITE_PARAM_COLOR, Filename]
						end,
						case Code of
							302 ->  [?TAB_GREEN_COLOR, <<"Redirect-to">>, ?WHITE_PARAM_COLOR, maps:get(<<"location">>, ResponseHeader, <<>>)];
							_ -> <<>>
						end,
					   ?TAB_GREEN_COLOR, <<"Status">>, ?WHITE_PARAM_COLOR, StatusText, <<"\n}">>],
					   
				TextBin = iolist_to_binary(TextData),
				NewState = case Code >= 400 of
								true  -> write_msg(error, TextBin, State#state{log_ult_reqhash = ReqHash});
								false -> write_msg(info,  TextBin, State#state{log_ult_reqhash = ReqHash})
							end,
				NewState;
			false -> 
				State
		end
	catch 
		_:ExceptionReason -> 
			format_error("ems_logger do_log_request format invalid message. Reason: ~p.\nRequest: \033[1;31m~p\033[0m\n.", [ExceptionReason, Request]),
			State#state{log_ult_reqhash = ReqHash}
	end.
	

