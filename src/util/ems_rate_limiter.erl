%%********************************************************************
%% @title Module ems_rate_limiter
%% @version 1.0.0
%% @doc Rate limiter module using ETS for high performance
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_rate_limiter).

-behavior(gen_server).

-include("include/ems_config.hrl").

%% API
-export([start/1, check/1, init_table/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TABLE, ems_rate_limiter_table).
-define(SERVER, ?MODULE).

%%====================================================================
%% API
%%====================================================================

start(_Service) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init_table() ->
    ets:new(?TABLE, [set, public, named_table, {write_concurrency, true}, {read_concurrency, true}]).

check(Ip) ->
    try
        Timestamp = ems_util:get_milliseconds() div 1000,
        Conf = ems_config:getConfig(),
        {TargetIp, Mask} = Conf#config.rate_limit_cidr_interno,
        case ems_util:match_cidr(Ip, TargetIp, Mask) of
            true -> check_limit(Ip, Timestamp, Conf#config.rate_limit_interno);
            false -> check_limit(Ip, Timestamp, Conf#config.rate_limit_externo)
        end
    catch
        C1:R1:S1 -> 
            ems_logger:error("ems_rate_limiter:check error. Class: ~p, Reason: ~p, Stack: ~p", [C1, R1, S1]),
            allow
    end.

check_limit(_Ip, _Timestamp, 0) -> allow;
check_limit(Ip, Timestamp, Limit) ->
    Key = {Ip, Timestamp},
    try
        Count = ets:update_counter(?TABLE, Key, {2, 1}, {Key, 0}),
        if 
            Count =< Limit -> allow;
            Count =< (Limit * 1.5) -> {tarpit, 1000};
            Count =< (Limit * 2) -> {tarpit, 5000};
            true -> block
        end
    catch
        C2:R2:S2 -> 
            ems_logger:error("ems_rate_limiter:check_limit error. Table: ~p, Key: ~p, Class: ~p, Reason: ~p, Stack: ~p", [?TABLE, Key, C2, R2, S2]),
            allow
    end.


%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    init_table(),
    % Cleaner timer: remove old entries every 10 seconds
    timer:send_interval(10000, clean),
    {ok, []}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(clean, State) ->
    CleanupTime = (ems_util:get_milliseconds() div 1000) - 2,
    clean_old_entries(CleanupTime),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% Internal functions
%%====================================================================

clean_old_entries(CleanupTime) ->
    MatchSpec = [{{{'_', '$1'}, '_'}, [{'<', '$1', CleanupTime}], [true]}],
    ets:select_delete(?TABLE, MatchSpec).
