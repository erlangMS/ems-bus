%%********************************************************************
%% @title Module ems_node_discovery
%% @version 1.0.0
%% @doc Responsible for discovering and caching service nodes.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_node_discovery).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([get_work_node/1]).

-spec get_work_node(#service{}) -> {ok, node()} | {error, atom()}.
get_work_node(#service{host = '', module = Module}) -> 
	case ets:lookup(ctrl_node_dispatch, Module) of
		[{_, Node}] -> {ok, Node};
		[] -> 
			Node = node(),
			ets:insert(ctrl_node_dispatch, {Module, Node}),
			{ok, Node}
	end;
get_work_node(#service{host = [], module = _Module}) -> {error, eunavailable_service};
get_work_node(#service{host = HostList, module = Module}) -> 
	case ets:lookup(ctrl_node_dispatch, Module) of
		[{_, Node}] -> {ok, Node};
		[] -> 
			case find_alive_node(HostList) of
				{ok, Node} ->
					ems_logger:info("Dispatcher selected node: ~p. Cookie: ~p", [Node, erlang:get_cookie()]), 
					ets:insert(ctrl_node_dispatch, {Module, Node}),
					{ok, Node};
				Error -> Error
			end
	end.

-spec find_alive_node(list(atom())) -> {ok, node()} | {error, eunavailable_service}.
find_alive_node([]) -> {error, eunavailable_service};
find_alive_node([Node|_]) ->
	case net_adm:ping(Node) of
		pong -> {ok, Node};
		pang -> {error, eunavailable_service}
	end.
