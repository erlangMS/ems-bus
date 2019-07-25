%%********************************************************************
%% @title Module ems_snmp_server
%% @version 1.0.0
%% @doc Main module HTTP server
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_snmp_server).

-behavior(gen_server). 

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Server API
-export([start/1, stop/0]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

% estado do servidor
-record(state, {listener=[],
				service,
				name
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
 


 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(Service = #service{start_timeout = StartTimeout}) ->
 	State = #state{service = Service},
 	{ok, State, StartTimeout}.

    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_call(Msg, _From, State) ->
	{reply, Msg, State}.

handle_info(State) ->
   {noreply, State}.

handle_info(timeout, State = #state{service = S = #service{name = Name, 
														    tcp_listen_address_t = ListenAddress_t,
														    properties = Props}}) ->
	S2 = ems_config:get_port_offset(S),
	ServerName = binary_to_list(iolist_to_binary([Name, <<"_port_">>, integer_to_binary(S2#service.tcp_port)])),

	SnmpAgentConfigPath0 = binary_to_list(maps:get(<<"snmp_agent_config_path">>, Props, <<>>)),
	SnmpManagerConfigPath0 = binary_to_list(maps:get(<<"snmp_manager_config_path">>, Props, <<>>)),
	SnmpAgentDBPath0 = binary_to_list(maps:get(<<"snmp_agent_db_path">>, Props, <<>>)),
	SnmpManagerDBPath0 = binary_to_list(maps:get(<<"snmp_manager_db_path">>, Props, <<>>)),
	
	SnmpAgentConfigPath = ems_util:parse_file_name_path(SnmpAgentConfigPath0, [{<<"PRIV_PATH">>, ?PRIV_PATH}], undefined),
	SnmpManagerConfigPath = ems_util:parse_file_name_path(SnmpManagerConfigPath0, [{<<"PRIV_PATH">>, ?PRIV_PATH}], undefined),
	SnmpAgentDBPath = ems_util:parse_file_name_path(SnmpAgentDBPath0, [{<<"PRIV_PATH">>, ?PRIV_PATH}], undefined),
	SnmpManagerDBPath = ems_util:parse_file_name_path(SnmpManagerDBPath0, [{<<"PRIV_PATH">>, ?PRIV_PATH}], undefined),
	SnmpMetricVerbosity = binary_to_atom(maps:get(<<"snmp_metric_verbosity">>, Props, <<"log">>), utf8),


	
	io:format("AgentSnmpConfigPath: ~p\n", [SnmpAgentConfigPath]),
	io:format("SnmpManagerConfigPath: ~p\n", [SnmpManagerConfigPath]),
	io:format("SnmpAgentDBPath: ~p\n", [SnmpAgentDBPath]),
	io:format("SnmpManagerDBPath: ~p\n", [SnmpManagerDBPath]),
	io:format("SnmpMetricVerbosity: ~p\n", [SnmpMetricVerbosity]),
	
	ems_util:ensure_dir_writable(SnmpAgentDBPath),
	ems_util:ensure_dir_writable(SnmpManagerDBPath),
	
	application:set_env(snmp, agent, [{config, [{dir, SnmpAgentConfigPath}, {force_load, true},{verbosity, debug}]}, {db_dir, SnmpAgentDBPath}, {agent_type, master}]),	
	application:set_env(snmp, manager, [{config, [{dir, SnmpManagerConfigPath},{db_dir, SnmpManagerDBPath}]}]),	
	snmp:start(),
	exometer:start(),
	metric_verbosity(SnmpMetricVerbosity),	
	add_reporter(),
	create_metrics(),	
	
	{noreply, State}.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% Internal functions
%%===================================================================

%% @doc Verbosity for SNMP by Exometer
%% Levels: silence | info | log | debug | trace.
metric_verbosity()-> snmpa:verbosity(master_agent, silence).
metric_verbosity(Type)-> snmpa:verbosity(master_agent, Type).


add_reporter()->
	exometer_report:add_reporter(exometer_report_snmp,[]). 


create_metrics()->	
	exometer:new([ems_logger_write_error], counter, [{snmp, [{value, 20000}]}]),	
	exometer:new([ems_logger_write_info],  counter, [{snmp, [{value, 20000}]}]),
	exometer:new([ems_logger_write_warn],  counter, [{snmp, [{value, 20000}]}]).	


%% @doc Update metric value by Exometer
inc_counter_metric(Name) -> exometer:update([Name], 1).
dec_counter_metric(Name) ->  exometer:update([Name], -1).
counter_metric(Name, Value) -> exometer:update([Name], Value).

%% @doc Delete a metric	
delete_metric(Name)-> exometer:delete([Name]).
