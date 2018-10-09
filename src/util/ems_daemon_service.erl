%%********************************************************************
%% @title Module ems_daemon_service
%% @version 1.0.0
%% @doc Module responsible for the execute daemon services
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_daemon_service).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").


-export([start/1, stop/1]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3, 
		 start_daemon/1, stop_daemon/1, kill_daemon/1, restart_daemon/1, watchdog_daemon/1]).


-record(state, {daemon_id, 
				name,
				pid,
				port,
				timeout,
				start_cmd,
				stop_cmd,
				kill_cmd,
				pidfile,
				pidfile_watchdog_timer,
				filename,
				filename_lastmodified_time,
				logfile,
				daemon_params_encode,
				daemon_params,
				daemon_watchdog,
				daemon_watchdog_policy,
				hotdeploy,
				scan_catalogs_jarfile,
				scan_catalogs_path,
				state}). 


%%====================================================================
%% Server API
%%====================================================================

start(Service = #service{name = Name}) ->
	ServerName = erlang:binary_to_atom(Name, utf8),
    gen_server:start_link({local, ServerName}, ?MODULE, Service, []).
 
stop(ServerName) ->
    gen_server:cast(ServerName, shutdown).

start_daemon(Request = #request{service = #service{owner = Owner}}) when is_tuple(Request) ->
	ServerName2 = erlang:binary_to_atom(Owner, utf8),
	gen_server:cast(ServerName2, start_daemon),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	};
start_daemon(ServerName) ->
	gen_server:cast(ServerName, start_daemon).

stop_daemon(Request = #request{service = #service{owner = Owner}}) when is_tuple(Request) ->
	ServerName2 = erlang:binary_to_atom(Owner, utf8),
	gen_server:cast(ServerName2, stop_daemon),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	};
stop_daemon(ServerName) ->
	gen_server:cast(ServerName, stop_daemon).

kill_daemon(Request = #request{service = #service{owner = Owner}}) when is_tuple(Request) ->
	ServerName2 = erlang:binary_to_atom(Owner, utf8),
	gen_server:cast(ServerName2, kill_daemon),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	};
kill_daemon(ServerName) ->
	gen_server:cast(ServerName, kill_daemon).

restart_daemon(Request = #request{service = #service{owner = Owner}}) when is_tuple(Request) ->
	ServerName2 = erlang:binary_to_atom(Owner, utf8),
	gen_server:cast(ServerName2, restart_daemon),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	};
restart_daemon(ServerName) ->
	gen_server:cast(ServerName, restart_daemon).

watchdog_daemon(Request = #request{service = #service{owner = Owner}}) when is_tuple(Request) ->
	ServerName2 = erlang:binary_to_atom(Owner, utf8),
	gen_server:cast(ServerName2, watchdog_daemon),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	};
watchdog_daemon(ServerName) ->
	gen_server:cast(ServerName, watchdog_daemon).

 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(#service{name = Name,
			  timeout = Timeout,
			  start_timeout = StartTimeout,
			  filename = FilenameService,
			  properties = Props}) ->
    NameStr = binary_to_list(Name),
    Port = maps:get(<<"port">>, Props, 0),
    StartCmd = ems_util:replace_config_and_custom_variables(parse_start_cmd(maps:get(<<"start_cmd">>, Props, <<>>))),
    StopCmd = ems_util:replace_config_and_custom_variables(maps:get(<<"stop_cmd">>, Props, <<>>)),
    KillCmd = ems_util:replace_config_and_custom_variables(maps:get(<<"kill_cmd">>, Props, <<>>)),
	PidFileWatchDogTimeOut = ems_util:parse_range(maps:get(<<"pidfile_watchdog_timer">>, Props, 30000), 0, 86400000),
    Filename = ems_util:replace_config_and_custom_variables(FilenameService),
    PidFile = ems_util:replace_config_and_custom_variables(maps:get(<<"pidfile">>, Props, <<>>)),
    Logfile = ems_util:replace_config_and_custom_variables(maps:get(<<"logfile">>, Props, <<>>)),
    DaemonParamsEncode = maps:get(<<"daemon_params_encode">>, Props, <<>>),
	DaemonParamsJson = binary_to_list(ems_util:json_encode(maps:get(<<"daemon_params">>, Props, <<"{}">>))),
    DaemonWatchdog = ems_util:parse_bool(maps:get(<<"daemon_watchdog">>, Props, false)),
	DaemonWachdogPolicy = parse_daemon_watchdog_policy(maps:get(<<"daemon_watchdog_policy">>, Props, <<"link">>)),
    Hotdeploy = ems_util:parse_bool(maps:get(<<"hotdeploy">>, Props, false)),
	LastModifiedTime = get_modified_time_filename(Name, Filename),
	ScanCatalogsJarfile = ems_util:parse_bool(maps:get(<<"scan_catalogs_jarfile">>, Props, false)),
	ScanCatalogsPath = binary_to_list(maps:get(<<"scan_catalogs_path">>, Props, <<>>)),
    State = #state{name = NameStr,
				   timeout = Timeout,
				   port = Port,
				   start_cmd = StartCmd,
				   stop_cmd = StopCmd,
				   kill_cmd = KillCmd,
				   pidfile = PidFile,
				   pidfile_watchdog_timer = PidFileWatchDogTimeOut,
				   daemon_id = "unknow",
				   filename = Filename,
				   logfile = Logfile,
				   daemon_params = DaemonParamsJson,
				   daemon_params_encode = DaemonParamsEncode,
				   daemon_watchdog = DaemonWatchdog,
				   daemon_watchdog_policy = DaemonWachdogPolicy,
				   hotdeploy = Hotdeploy,
				   filename_lastmodified_time = LastModifiedTime,
				   scan_catalogs_jarfile = ScanCatalogsJarfile,
				   scan_catalogs_path = ScanCatalogsPath,
				   state = start},
    {ok, State, StartTimeout}.
    
handle_cast(start_daemon, State = #state{timeout = Timeout}) ->
	State2 = do_start_daemon(State),
    {noreply, State2, Timeout};

handle_cast(stop_daemon, State) ->
	State2 = do_stop_daemon(State),
    {noreply, State2};

handle_cast(kill_daemon, State) ->
	State2 = do_kill_daemon(State),
    {noreply, State2};

handle_cast(restart_daemon, State = #state{name = Name, timeout = Timeout}) ->
	Msg = io_lib:format("ems_daemon_service ~s daemon restarting...", [Name]),
	State2 = do_restart_daemon(Msg, State, info),
    {noreply, State2, Timeout};

handle_cast(watchdog_daemon, State = #state{timeout = Timeout}) ->
	State2 = do_daemon_watchdog(State),
    {noreply, State2, Timeout};

handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_, State) ->
	{noreply, State}.

handle_call(_, _From, State) ->
	{reply, ok, State}.

handle_info(timeout, State = #state{state = start}) ->
	State2 = do_start_daemon(State),
	{noreply, State2, State2#state.timeout};

handle_info(timeout, State = #state{state = stopped}) ->
	{noreply, State};

handle_info(timeout, State = #state{state = monitoring}) ->
	State2 = do_daemon_watchdog(State),
	{noreply, State2, State2#state.timeout}.


terminate(_, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    
    
%%====================================================================
%% Internal functions
%%====================================================================

do_start_daemon(State = #state{start_cmd = CmdStart, 
							   port = Port,
							   name = Name,
							   pidfile = Pidfile,
							   daemon_watchdog_policy = DaemonWatchdogPolicy}) ->
	DaemonId = integer_to_list(ems_util:get_milliseconds()),
	case ems_util:get_pid_from_port(Port) of
		{ok, CurrentPid} -> 
			case DaemonWatchdogPolicy of
				restart -> 
					Msg = io_lib:format("ems_daemon_service ~s daemon already exist with pid ~p, restart policy in progress...", [Name, CurrentPid]),
					ems_logger:warn(Msg),
					do_restart_daemon(Msg, State#state{pid = CurrentPid, daemon_id = "unknow"}, error);
				'link' ->
					Msg = io_lib:format("ems_daemon_service ~s daemon already exist with pid ~p, link policy in progress...", [Name, CurrentPid]),
					ems_logger:warn(Msg),
					do_link_daemon(DaemonId, State);
				none -> 
					Msg = io_lib:format("ems_daemon_service ~s daemon already exist with pid ~p, none policy in progress...", [Name, CurrentPid]),
					ems_logger:warn(Msg)
			end;
		_ ->
			Pidfile2 = parse_variables(Pidfile, State#state{daemon_id = DaemonId}),
			CmdStart2 = parse_variables(CmdStart, State#state{daemon_id = DaemonId, pidfile = Pidfile2}),
			ems_logger:info("ems_daemon_service ~s starting new daemon. \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, CmdStart2]),
			case CmdStart2 =/= "" of
				true ->
					% antes de subir o daemon é preciso excluir o pid (na verdade o pid não deveria existir)
					case delete_pidfile(State#state{daemon_id = DaemonId}) of
						ok ->
							case ems_util:os_command(CmdStart2, #{ max_size => 0 }) of
								{ok, _Result} -> 
									do_link_daemon(DaemonId, State);
								{error, einvalid_command} ->
									ems_logger:error("ems_daemon_service ~s failed to start daemon with invalid start_cmd parameter. \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, CmdStart2]),
									State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
							end;
						{error, Reason} ->
							ems_logger:error("ems_daemon_service ~s failed to start daemon because could not delete pidfile ~p. Reason: ~p. \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, Pidfile2, Reason, CmdStart2]),
							State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
					end;
				false ->
					ems_logger:error("ems_daemon_service ~s failed to start daemon because start_cmd parameter is empty.", [Name]),
					State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
			end
	end.
	
do_link_daemon(DaemonId, State = #state{port = Port,
										name = Name,
										filename = Filename,
										daemon_watchdog_policy = DaemonWatchdogPolicy}) ->
	case fica_em_loop_ate_obter_pid(Name, Port, 0, 60) of
		{ok, Pid} -> 
			case DaemonWatchdogPolicy of
				restart -> ems_logger:info("ems_daemon_service ~s new daemon started (Pid: ~p Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]);
				'link' -> ems_logger:info("ems_daemon_service ~s daemon linked (Pid: ~p Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId])
			end,
			State2 = State#state{state = monitoring, 
								 pid = Pid, 
								 daemon_id = DaemonId, 
								 filename_lastmodified_time = get_modified_time_filename(Name, Filename)},
			do_scan_catalogs(State2);
		_ -> 
			case DaemonWatchdogPolicy of
				restart -> ems_logger:error("ems_daemon_service ~s start new daemon failed because does not adquire pid of current daemon.", [Name]);
				'link' -> ems_logger:error("ems_daemon_service ~s daemon link failed because does not adquire pid of current daemon.", [Name])
			end,
			State#state{state = start, pid = undefined, daemon_id = "unknow"}
	end.
	

do_stop_daemon(State = #state{stop_cmd = CmdStop, 
							  name = Name,
							  port = Port,
							  pid = Pid,
							  daemon_id = DaemonId}) ->
	CmdStop2 = parse_variables(CmdStop, State),
    ems_logger:info("ems_daemon_service ~s stopping daemon (Pid: ~p, Port: ~p, DaemonId: ~s). \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, Pid, Port, DaemonId, CmdStop2]),
    case CmdStop2 =/= "" of
		true ->
			case ems_util:os_command(CmdStop2, #{ max_size => 0 }) of
				{ok, _Result} ->
					fica_em_loop_ate_encerrar_pid(Port, Pid, 30),
					case ems_util:get_pid_from_port(Port) of
						{ok, Pid2} when Pid2 =:= Pid -> 
							ems_logger:warn("ems_daemon_service ~s daemon seems to be dead, killing him (Pid: ~p Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]),
							do_kill_daemon(State);  % já que não finalizou normalmente, vai a força
						_ -> 
							ems_logger:info("ems_daemon_service ~s daemon stopped (Pid: ~p Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]),
							delete_pidfile(State),  % apenas para garantir, o processo que é o dono do arquivo já deve ter feito
							State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
					end;
				{error, einvalid_command} ->
					ems_logger:error("ems_daemon_service ~s failed to stop daemon with stop_cmd parameter. \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, CmdStop2]),
					State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
			end;
		false ->
			ems_logger:error("ems_daemon_service ~s failed to stop daemon because stop_cmd parameter is empty.", [Name]),
			State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
	end.
	

do_kill_daemon(State = #state{kill_cmd = CmdStop, 
							  name = Name,
							  port = Port,
							  pid = Pid,
							  daemon_id = DaemonId}) ->
	CmdStop2 = parse_variables(CmdStop, State),
    ems_logger:info("ems_daemon_service ~s killing daemon (Pid: ~p, Port: ~p, DaemonId: ~s). \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, Pid, Port, DaemonId, CmdStop2]),
    case CmdStop2 =/= "" of
		true ->
			case ems_util:os_command(CmdStop2, #{ max_size => 0 }) of
				{ok, _Result} ->
					ems_logger:info("ems_daemon_service ~s daemon killed (Pid: ~p Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]),
					delete_pidfile(State),  % apenas para garantir, o processo que é o dono do arquivo já deve ter feito
					State#state{state = stopped, pid = undefined, daemon_id = "unknow"};
				{error, einvalid_command} ->
					ems_logger:error("ems_daemon_service ~s failed to kill daemon with kill_cmd parameter. \033[0;32mOS Command\033[0m: \033[01;34m~s\033[0m.", [Name, CmdStop2]),
					State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
			end;
		false ->
			ems_logger:error("ems_daemon_service ~s failed to kill daemon because kill_cmd parameter is empty.", [Name]),
			State#state{state = stopped, pid = undefined, daemon_id = "unknow"}
	end.


do_restart_daemon(Message, State, MsgType) ->
	case MsgType of
		error -> ems_logger:error(Message);
		_ -> ems_logger:info(Message)
	end,
	State2 = do_stop_daemon(State),
	do_start_daemon(State2).


% Monitora o processo externo executado por start_cmd para verificar se está vivo
% Se o processo morrer outro será reiniciado
% Além disso, se pidfile_watchdog_timer > 0, testa se o pid está atualizado
% nós verificamos também se uma nova versão do cmd deve ser executado quando o executável for mais novo
do_daemon_watchdog(State = #state{name = Name,
							 port = Port,
							 pid = Pid,
						     pidfile_watchdog_timer = PidFileWatchdogTimeout,
							 daemon_id = DaemonId,
							 hotdeploy = Hotdeploy,
							 filename = Filename,
							 daemon_watchdog = DaemonWatchdog,
							 daemon_watchdog_policy = DaemonWatchdogPolicy}) ->
	
	% Quando hotdeploy é true e existe uma nova versão do executável
	% então reinicia o daemon
	% caso contrário apenas verifica se o daemon atual está vivo e saudável
	case Hotdeploy andalso exist_new_version(State) of
		true -> 
			Msg = io_lib:format("ems_daemon_service ~s hotdeploy daemon \033[01;34m\"~s\"\033[0m...", [Name, Filename]),
			do_restart_daemon(Msg, State, info);
		false ->
			% para verificar o daemon atual, o flag DaemonWatchdog deve estar true
			case DaemonWatchdog of
				true ->
					?DEBUG("ems_daemon_service ~s if daemon is ok (Pid: ~p, Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]),
					case ems_util:get_pid_from_port(Port) of
						{ok, CurrentPid} -> 
							case CurrentPid == Pid of
								true ->
									case PidFileWatchdogTimeout > 0 of
										true -> 
											do_pidfile_watchdog_check(State, 1);
										false ->
											?DEBUG("ems_daemon_service ~s daemon is ok (Pid: ~p, Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]),
											State#state{state = monitoring}
									end;
								false ->
									case DaemonWatchdogPolicy == restart orelse DaemonWatchdogPolicy == 'link' of
										true ->
											% o pid não é o mesmo então outro processo foi iniciado pelo sistema operacional
											% não podemos permitir isso pois é o ems_daemon_service o responsável pelo processo
											Msg = io_lib:format("ems_daemon_service ~s will be restarted because unknow pid detected (Pid: ~p, OtherPid: ~p, DaemonWatchdogPolicy: ~p).", [Name, Pid, CurrentPid, DaemonWatchdogPolicy]),
											do_restart_daemon(Msg, State, error);
										false ->
											Msg = io_lib:format("ems_daemon_service ~s unknow pid detected (Pid: ~p, OtherPid: ~p, DaemonWatchdogPolicy: none).", [Name, Pid, CurrentPid]),
											ems_logger:warn(Msg),
											State#state{state = monitoring}
									end
							end;	
						_ ->
							% O pid não existe mais, inicia um novo processo
							ems_logger:error("ems_daemon_service ~s will start again because the current daemon ~p was killed in the operating system.", [Name, Pid]),
							delete_pidfile(State),  % o processo foi morto mas pode ter deixado um arquivo de pid, vamos fazer a limpeza
							do_start_daemon(State)
					end;
				false -> State#state{state = monitor}
			end
	end.


% O processo executado pelo start_cmd é responsável por atualizar seu próprio arquivo de pid (a menos que watchdog não seja usado)
% Se o timestamp do arquivo de pid estiver desatualiado, o processo será reiniciado pois pode indicar que o processo travou
% O teste é realizado pelo menos 3 vezes para ser conservador com intervalos de 1 segundo
do_pidfile_watchdog_check(State = #state{name = Name,
								 port = Port,
								 pid = Pid,
								 pidfile = PidFile,
								 pidfile_watchdog_timer = PidFileWatchdogTimeout,
								 daemon_id = DaemonId,
								 daemon_watchdog_policy = DaemonWatchdogPolicy}, 
						  Tentativa) ->
	% mostra mensagem apenas na primeira tentativa
	case Tentativa == 1 of
		true -> ?DEBUG("ems_daemon_service ~s check pidfile daemon (Pid: ~p, Port: ~p, DaemonId: ~s).", [Name, Pid, Port, DaemonId]);
		false -> ok
	end,
	Pidfile2 = parse_variables(PidFile, State),
	case Pidfile2 =/= "" of
		true ->
			% verifica o timestamp do arquivo de pid, se ficar desatualizado, será reiniciado
			case file:read_file_info(Pidfile2, []) of
				{ok, {file_info, _FSize, _Type, _Access, _ATime, MTime, _CTime, _Mode,_,_,_,_,_,_}} -> 
					TimeAtual = calendar:datetime_to_gregorian_seconds(calendar:local_time()),
					TimePidfile = calendar:datetime_to_gregorian_seconds(MTime),
					DiffTime = erlang:abs((TimeAtual - TimePidfile) * 1000),
					case DiffTime > (PidFileWatchdogTimeout + 15000) of % 15 segundos a mais para eventuais delays
						true -> 
							case Tentativa == 3 of
								true ->
									case DaemonWatchdogPolicy == restart orelse DaemonWatchdogPolicy == 'link' of
										true ->
											Msg = io_lib:format("ems_daemon_service ~s pidfile \033[01;34m\"~s\"\033[0m\033[00;31m is ~pms outdated, restart in progress (Pid: ~p, Port: ~p, DaemonId: ~s, DaemonWatchdogPolicy: ~p).", [Name, Pidfile2, DiffTime, Pid, Port, DaemonId, DaemonWatchdogPolicy]),
											do_restart_daemon(Msg, State, error);
										false ->
											Msg = io_lib:format("ems_daemon_service ~s pidfile \033[01;34m\"~s\"\033[0m\033[00;31m is ~pms outdated (Pid: ~p, Port: ~p, DaemonId: ~s, DaemonWatchdogPolicy: none).", [Name, Pidfile2, DiffTime, Pid, Port, DaemonId]),
											ems_logger:warn(Msg),
											State#state{state = monitoring}
									end;
								false -> 
									ems_util:sleep(1),
									do_pidfile_watchdog_check(State, Tentativa + 1)
							end;
						false -> 
							State#state{pid = Pid, state = monitoring}
					end;
				{error, enoent} -> 
					case Tentativa == 3 of
						true -> 
							case DaemonWatchdogPolicy == restart orelse DaemonWatchdogPolicy == 'link' of
								true ->
									Msg = io_lib:format("ems_daemon_service ~s pidfile \033[01;34m\"~s\"\033[0m\033[00;31m does not exist, restart in progress (Pid: ~p, Port: ~p, DaemonId: ~s, DaemonWatchdogPolicy: ~p).", [Name, Pidfile2, Pid, Port, DaemonId, DaemonWatchdogPolicy]),
									do_restart_daemon(Msg, State, error);
								false ->
									Msg = io_lib:format("ems_daemon_service ~s pidfile \033[01;34m\"~s\"\033[0m\033[00;31m does not exist, restart in progress (Pid: ~p, Port: ~p, DaemonId: ~s, DaemonWatchdogPolicy: none).", [Name, Pidfile2, Pid, Port, DaemonId]),
									ems_logger:warn(Msg),
									State#state{state = monitoring}
							end;
						false -> do_pidfile_watchdog_check(State, Tentativa + 1)
					end;
				{error, Reason} -> 
					ems_logger:error("ems_daemon_service ~s pidfile \033[01;34m\"~s\"\033[0m\033[00;31m is not accessible by the ErlangMS. Reason: ~p (Pid: ~p, Port: ~p, DaemonId: ~s).", [Name, Pidfile2, Reason, Pid, Port, DaemonId]),
					State#state{state = monitoring}
			end;
		false -> State#state{state = monitoring}
	end.


do_scan_catalogs(State = #state{scan_catalogs_path = <<>>}) -> State;
do_scan_catalogs(State = #state{name = Name, 
								scan_catalogs_jarfile = ScanCatalogsJarFile,
								scan_catalogs_path = ScanCatalogsPath,
							    filename = Filename}) ->
	% Para scanear catálogos a propriedade ScanCatalogsPath deve ter um path definido
	% Note que pode ser um path relativo pois pode ser em relação ao que está dentro do jar quando ScanCatalogsJarFile = true
	CatName = list_to_binary(Name),
	case ScanCatalogsJarFile == true of
		true -> 
			case do_scan_catalogs_jarfile(State) of
				{ok, CatFilename} ->
					ems_logger:info("ems_daemon_service ~s scan catalogs on \033[01;34m\"~s\"\033[0m of jarfile \033[01;34m\"~s\"\033[0m\033[00;33m.", [Name, ScanCatalogsPath, Filename]),
					ems_config:add_catalog(CatName, CatFilename),
					ems_json_loader:sync_full(ems_catalog_loader_fs);
				{error, Reason} ->
					ems_logger:error("ems_daemon_service ~s scan catalogs failed on \033[01;34m\"~s\"\033[0m of jarfile \033[01;34m\"~s\"\033[0m\033[00;33m. Reason: ~p", [Name, ScanCatalogsPath, Filename, Reason])
			end;
		false -> 
			ems_logger:info("ems_daemon_service ~s scan catalogs on \033[01;34m\"~s\"\033[0m\033[00;33m.", [Name, ScanCatalogsPath]),
			ems_config:add_catalog(CatName, ScanCatalogsPath),
			ems_json_loader:sync_full(ems_catalog_loader_fs)
	end,
	State.
		
do_scan_catalogs_jarfile(#state{filename = Filename,	
								scan_catalogs_path = ScanCatalogsPath}) ->
	try
		CatTempDir = filename:join([?TEMP_PATH, "catalogs", "jarfile", filename:basename(Filename)]),
		zip:unzip(Filename, [{cwd, CatTempDir}]),
		{ok, filename:join([CatTempDir, ScanCatalogsPath])}
	catch
		_:_ -> {error, eno_jarfile}
	end.


% Fica em um loop até conseguir obter o pid por meio da porta utilizada pelo processo externo
fica_em_loop_ate_obter_pid(_,_, _, 0) -> {error, enoent};
fica_em_loop_ate_obter_pid(Name, Port, Timeout, Tentativas) ->
	ems_util:sleep(3000),
	case ems_util:get_pid_from_port(Port) of
		{ok, Pid} -> {ok, Pid};
		_ -> 
			% Imprime warning depois de 30 segundos
			case Timeout > 30000 of
				true -> ems_logger:warn("ems_daemon_service ~s failed get pid from port ~p (Tentativas: ~p).", [Name, Port, Tentativas]);
				false -> ok
			end,
			fica_em_loop_ate_obter_pid(Name, Port, Timeout + 3000, Tentativas - 1)
	end.

				
% Fica em um loop até o pid ser encerrado
fica_em_loop_ate_encerrar_pid(_, _, 0) -> ok;
fica_em_loop_ate_encerrar_pid(Port, Pid, Tentativas) ->
	ems_util:sleep(3000),
	case ems_util:get_pid_from_port(Port) of
		{ok, Pid2} when Pid2 =:= Pid -> 
			fica_em_loop_ate_encerrar_pid(Port, Pid, Tentativas - 1);
		_ -> ok
	end.
									
	
% O comando cmd_start precisa ter um & no final para o barramento não ficar preso 
% com a execução do comando
parse_start_cmd(<<>>) -> "";
parse_start_cmd(Cmd) -> 
	CmdStr = string:trim(binary_to_list(Cmd)),
	case CmdStr =/= "" of
		true ->
			case lists:reverse(CmdStr) of
				"&" ++ _ -> CmdStr;
				_ -> CmdStr ++ " &"
			end;
		false -> ""
	end.
			
			
parse_variables(<<>>, _) -> "";
parse_variables(Str, #state{daemon_id = DaemonId,
							pid = Pid,
						    port = Port,
						    name = Name,
						    pidfile = Pidfile,
						    pidfile_watchdog_timer = PidfileWatchdogTimer,
						    filename = Filename,
						    logfile = Logfile,
						    daemon_params = DaemonParams,
						    daemon_params_encode = DaemonParamsEncode}) ->
	Conf = ems_config:getConfig(),
    DaemonParams2 = ems_util:replace_all_vars_and_custom_variables(DaemonParams, 
    		[{<<"PORT">>, integer_to_list(Port)},
			 {<<"DAEMON_SERVICE">>, Name},
			 {<<"DAEMON_ID">>, DaemonId},
			 {<<"DAEMON_PID">>, ems_util:integer_to_list_def(Pid, "unknow")},
			 {<<"FILENAME">>, Filename},
			 {<<"LOGFILE">>, Logfile},
			 {<<"PIDFILE_WATCHDOG_TIMER">>, integer_to_list(PidfileWatchdogTimer)},
			 {<<"PIDFILE">>, Pidfile},
			 {<<"JAVA_HOME">>, Conf#config.java_home},
			 {<<"JAVA_THREAD_POOL">>, Conf#config.java_thread_pool},
			 {<<"JAVA_JAR_PATH">>, Conf#config.java_jar_path},
			 {<<"REST_BASE_URL">>, binary_to_list(Conf#config.rest_base_url)},
			 {<<"REST_ENVIRONMENT">>, Conf#config.rest_environment},
			 {<<"REST_USER">>, Conf#config.rest_user},
			 {<<"REST_PASSWD">>, Conf#config.rest_passwd},
			 {<<"LDAP_URL">>, Conf#config.ldap_url},
			 {<<"LDAP_ADMIN">>, Conf#config.ldap_admin},
			 {<<"LDAP_PASSWD">>, Conf#config.ldap_password_admin},
			 {<<"SMTP_FROM">>, Conf#config.smtp_from},
			 {<<"SMTP_PASSWD">>, Conf#config.smtp_passwd},
			 {<<"SMTP_PORT">>, Conf#config.smtp_port},
			 {<<"SMTP_MAIL">>, Conf#config.smtp_mail},
			 {<<"PRIV_PATH">>, ?PRIV_PATH}
			]), 
    DaemonParams3 = case DaemonParamsEncode of
						<<"base64">> -> list_to_binary("'base64:" ++ base64:encode_to_string(DaemonParams2) ++ "'");
						_ -> list_to_binary("'" ++ DaemonParams2 ++ "'")
				    end,
	Result = ems_util:replace_all_vars_and_custom_variables(Str, 
		[{<<"PORT">>, integer_to_list(Port)},
		 {<<"DAEMON_SERVICE">>, Name},
		 {<<"DAEMON_ID">>, DaemonId},
		 {<<"DAEMON_PID">>, ems_util:integer_to_list_def(Pid, "unknow")},
		 {<<"DAEMON_PARAMS">>, DaemonParams3},
		 {<<"FILENAME">>, Filename},
		 {<<"LOGFILE">>, Logfile},
		 {<<"PIDFILE_WATCHDOG_TIMER">>, integer_to_list(PidfileWatchdogTimer)},
		 {<<"PIDFILE">>, Pidfile},
		 {<<"JAVA_HOME">>, Conf#config.java_home},
		 {<<"JAVA_THREAD_POOL">>, Conf#config.java_thread_pool},
		 {<<"JAVA_JAR_PATH">>, Conf#config.java_jar_path},
		 {<<"REST_BASE_URL">>, binary_to_list(Conf#config.rest_base_url)},
		 {<<"REST_ENVIRONMENT">>, Conf#config.rest_environment},
		 {<<"REST_USER">>, Conf#config.rest_user},
		 {<<"REST_PASSWD">>, Conf#config.rest_passwd},
		 {<<"LDAP_URL">>, Conf#config.ldap_url},
		 {<<"LDAP_ADMIN">>, Conf#config.ldap_admin},
		 {<<"LDAP_PASSWD">>, Conf#config.ldap_password_admin},
		 {<<"SMTP_FROM">>, Conf#config.smtp_from},
		 {<<"SMTP_PASSWD">>, Conf#config.smtp_passwd},
		 {<<"SMTP_PORT">>, Conf#config.smtp_port},
		 {<<"SMTP_MAIL">>, Conf#config.smtp_mail},
		 {<<"PRIV_PATH">>, ?PRIV_PATH}
		]), 
	Result.


delete_pidfile(State = #state{name = Name,
							  pidfile = Pidfile}) ->
	Pidfile2 = parse_variables(Pidfile, State),
	case Pidfile2 =/= "" of
		true ->
			case file:delete(Pidfile2) of
				ok -> 
					ems_logger:warn("ems_daemon_service ~s pidfile \033[01;34m\"~s\"\033[0m\033[00;33m deleted.", [Name, Pidfile2]),
					ok;
				{error, enoent} -> ok;  % ok, pid não existe
				Error -> Error
			end;
		false -> ok
	end.

exist_new_version(#state{hotdeploy = false}) -> false;
exist_new_version(#state{name = Name, 
						 filename = Filename,
						 filename_lastmodified_time = LastModifiedTime,
						 hotdeploy = true}) ->
	CurrentModifiedTime = get_modified_time_filename(Name, Filename),
	CurrentModifiedTime =/= undefined andalso LastModifiedTime =/= undefined andalso LastModifiedTime =/= CurrentModifiedTime.
								 
get_modified_time_filename(Name, Filename) ->
	case Filename =/= "" of
		true ->
			case file:read_file_info(Filename, []) of
				{ok,{file_info, _FSize, _Type, _Access, _ATime, MTime, _CTime, _Mode,_,_,_,_,_,_}} -> 
					calendar:datetime_to_gregorian_seconds(MTime);
				{error, Reason} -> 
					ems_logger:warn("ems_daemon_service ~s get_modified_time_filename failed. Reason: ~p.", [Name, Reason]),
					undefined
			end;
		false ->
			undefined
	end.

parse_daemon_watchdog_policy(<<>>) -> none;
parse_daemon_watchdog_policy(<<"restart">>) -> restart;
parse_daemon_watchdog_policy(<<"link">>) -> 'link';
parse_daemon_watchdog_policy(<<"none">>) -> none;
parse_daemon_watchdog_policy(_) -> throw(einvalid_daemon_watchdog_policy).


