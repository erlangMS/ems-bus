%%********************************************************************
%% @title Module ems_http_server
%% @version 1.0.0
%% @doc Main module HTTP server
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_http_server).

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
														    tcp_listen_address_t = ListenAddress_t}}) ->
	S2 = ems_config:get_port_offset(S),
	ServerName = binary_to_list(iolist_to_binary([Name, <<"_port_">>, integer_to_binary(S2#service.tcp_port)])),
	case start_listeners(ListenAddress_t, S2, ServerName, 1, State) of
		{ok, State2} ->	{noreply, State2};
		{error, Reason, State2} -> 
			ems_logger:error("ems_http_server failed to start listeners. Reason: ~p.", [Reason]),
			{noreply, State2}
	end.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

	
%%====================================================================
%% Internal functions
%%====================================================================

start_listeners([], _Service, _ServerName, _ListenerNo, State) -> {ok, State};
start_listeners([H|T], Service, ServerName, ListenerNo, State) ->
	ListenerName = list_to_atom(ServerName ++ "_listener_" ++ integer_to_list(ListenerNo)),
	case do_start_listener(H, Service, ListenerName, State) of
		{ok, NewState} -> start_listeners(T, Service, ServerName, ListenerNo+1, NewState);
		{{error, Reason}, NewState} -> {error, Reason, NewState}
	end.

do_start_listener(IpAddress, Service = #service{tcp_port = Port}, ListenerName, State) ->
	case ems_http_listener:start(IpAddress, Service, ListenerName) of
		{ok, PidListener} ->
			NewState = State#state{listener=[{PidListener, Port, IpAddress}|State#state.listener]},
			{ok, NewState};
		{error, Reason} ->
			{{error, Reason}, State}
	end.

	

	
	
