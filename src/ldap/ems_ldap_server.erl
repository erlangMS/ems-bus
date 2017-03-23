%%********************************************************************
%% @title Module ems_ldap_server
%% @version 1.0.0
%% @doc Main module ldap server
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_ldap_server).

-behavior(gen_server). 

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").

%% Server API
-export([start/1, stop/0]).


%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

% estado do servidor
-record(state, {listener=[],
				tcp_config,
				name
		}).

-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start(Service = #service{name = Name}) -> 
 	ServerName = list_to_atom(binary_to_list(Name)),
    gen_server:start_link({local, ServerName}, ?MODULE, Service, []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 


 
%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init(Service = #service{name = Name, 
						tcp_listen_address_t = ListenAddress_t,
						properties = Props}) ->
 	ServerName = binary_to_list(Name),
 	State = #state{tcp_config = Service, name = ServerName},
	case start_listeners(ListenAddress_t, Service, ServerName, Service, 1, State) of
		{ok, State2} ->
			{ok, State2};
		{error, _Reason, State2} -> 
			{stop, State2}
	end.
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_call(Msg, _From, State) ->
	{reply, Msg, State}.

handle_info(State) ->
   {noreply, State}.

handle_info(_Msg, State) ->
   {noreply, State}.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

	
%%====================================================================
%% Internal functions
%%====================================================================

start_listeners([], _Service, _ServerName, _Service, _ListenerNo, State) -> {ok, State};
start_listeners([H|T], Service, ServerName, Service, ListenerNo, State) ->
	ListenerName = list_to_atom(ServerName ++ "_listener_" ++ integer_to_list(ListenerNo)),
	case do_start_listener(H, Service, ListenerName, Service, State) of
		{ok, NewState} -> start_listeners(T, Service, ServerName, Service, ListenerNo+1, NewState);
		{{error, Reason}, NewState} -> {error, Reason, NewState}
	end.

do_start_listener(IpAddress, Service = #service{tcp_port = Port}, ListenerName, Service, State) ->
	case ems_ldap_listener:start(IpAddress, Service, ListenerName, Service) of
		{ok, PidListener} ->
			NewState = State#state{listener=[{PidListener, Port, IpAddress}|State#state.listener]},
			{ok, NewState};
		{error, Reason} ->
			{{error, Reason}, State}
	end.
	
