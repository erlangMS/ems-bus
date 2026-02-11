-module(ems_node_discovery).

-behaviour(gen_server).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% API
-export([start/1, stop/0, get_work_node/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {tref = undefined}).

-define(DISCOVERY_TIMEOUT, 60000). % 1 minute

%% API Functions

start(_Args) ->
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:call(?MODULE, stop).

-spec get_work_node(#service{}) -> {ok, node()} | {error, atom()}.
get_work_node(#service{host = '', module = Module}) -> 
	case ets:lookup(ctrl_node_dispatch, Module) of
		[{_, Node}] -> {ok, Node};
		[] -> 
			Node = node(),
			ets:insert(ctrl_node_dispatch, {Module, Node}),
			{ok, Node}
	end;
get_work_node(#service{host = WorkNode, module = Module}) -> 
	case ets:lookup(ctrl_node_dispatch, Module) of
		[{_, Node}] -> {ok, Node};
		[] -> 
			case is_alive_node(WorkNode) of
				true ->
					ems_logger:info("Dispatcher selected node (manual discovery): ~p. Cookie: ~p", [WorkNode, erlang:get_cookie()]), 
					ets:insert(ctrl_node_dispatch, {Module, WorkNode}),
					{ok, WorkNode};
				false -> {error, eunavailable_service}
			end
	end.


%% gen_server callbacks

init([]) ->
    self() ! sweep,
    {ok, #state{}}.

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(sweep, State) ->
    ems_logger:debug("ems_node_discovery sweep started."),
    do_sweep(),
    TRef = erlang:send_after(?DISCOVERY_TIMEOUT, self(), sweep),
    {noreply, State#state{tref = TRef}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% Internal functions

-spec is_alive_node(node()) -> boolean().
is_alive_node(Node) ->
	case is_atom(Node) andalso (Node == node() orelse lists:member(Node, nodes())) of
		true -> true;
		false -> 
			case is_atom(Node) andalso Node =/= '' andalso Node =/= undefined andalso Node =/= null of
				true -> net_adm:ping(Node) == pong;
				false -> false
			end
	end.

do_sweep() ->
    try
        Tables = [ets_catalog_get_db, ets_catalog_post_db, ets_catalog_put_db, ets_catalog_delete_db, ets_catalog_options_db, ets_catalog_kernel_db,
                  ets_catalog_get_fs, ets_catalog_post_fs, ets_catalog_put_fs, ets_catalog_delete_fs, ets_catalog_options_fs, ets_catalog_kernel_fs],
        lists:foreach(fun(Table) ->
            case ets:info(Table) of
                undefined -> ok;
                _ ->
                    Records = ets:tab2list(Table),
                    lists:foreach(fun(#service{host = Host, module = Module, enable = true}) ->
                                        case is_atom(Host) andalso Host =/= '' andalso Host =/= undefined andalso Host =/= null of
                                            true ->
                                                case ets:lookup(ctrl_node_dispatch, Module) of
                                                    [] -> 
                                                        case is_alive_node(Host) of
                                                            true -> 
                                                                ems_logger:info("Dispatcher discovery: ~p.", [Host]),
                                                                ets:insert(ctrl_node_dispatch, {Module, Host});
                                                            false -> ok
                                                        end;
                                                    _ -> ok % Already cached
                                                end;
                                            false -> ok
                                        end;
                                     (_) -> ok
                                  end, Records)
            end
        end, Tables),
        ems_logger:debug("ems_node_discovery sweep finished.")
    catch
        _Exception:Reason ->
            ems_logger:warn("ems_node_discovery sweep failed: ~p.", [Reason])
    end.
