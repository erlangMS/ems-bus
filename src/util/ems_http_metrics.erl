%%********************************************************************
%% @title Module ems_http_metrics
%% @version 1.0.0
%% @doc RED metrics collector using atomic ETS counters.
%%      Tracks HTTP request histogram, cache hit/miss, and log events.
%%      All write operations are lock-free (ets:update_counter NIF).
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_http_metrics).

-export([new/0,
         observe/4,
         inc_cache_hit/0, inc_cache_miss/0,
         inc_log/1,
         label_sets/0,
         get_counter/1]).

%% Prometheus histogram bucket thresholds in seconds, paired with their
%% pre-formatted binary labels. Matching Micrometer Spring Boot defaults.
-define(BUCKET_DEFS, [
    {0.001, <<"0.001">>},
    {0.005, <<"0.005">>},
    {0.01,  <<"0.01">>},
    {0.025, <<"0.025">>},
    {0.05,  <<"0.05">>},
    {0.1,   <<"0.1">>},
    {0.25,  <<"0.25">>},
    {0.5,   <<"0.5">>},
    {1.0,   <<"1.0">>},
    {2.5,   <<"2.5">>},
    {5.0,   <<"5.0">>},
    {10.0,  <<"10.0">>}
]).

-export_type([bucket_defs/0]).
-type bucket_defs() :: [{float(), binary()}].


%%====================================================================
%% Public API
%%====================================================================

%% Called once during application startup (ems_bus_app:start/2).
new() ->
    ets:new(ems_http_metrics, [named_table, public, set,
                                {write_concurrency, true},
                                {read_concurrency, true}]),
    ets:new(ems_http_metric_labels, [named_table, public, set,
                                      {write_concurrency, true},
                                      {read_concurrency, true}]).

%% Records one HTTP request observation into the histogram.
%% Called in ems_http_handler after each dispatched request.
%%   Method     :: binary()  — HTTP verb (<<"GET">>, <<"POST">>, ...)
%%   Uri        :: binary()  — service URL pattern from catalog
%%   Status     :: integer() — HTTP response code (200, 404, 500 ...)
%%   LatencyMs  :: integer() — milliseconds from request start to response
observe(Method, Uri, Status, LatencyMs) ->
    LatencySec = LatencyMs / 1000.0,
    Key = {Method, Uri, Status},
    ets:insert(ems_http_metric_labels, {Key}),
    lists:foreach(fun({Le, _LeBin}) ->
        case LatencySec =< Le of
            true  -> inc({bucket, Method, Uri, Status, Le});
            false -> ok
        end
    end, ?BUCKET_DEFS),
    inc({bucket, Method, Uri, Status, infinity}),
    inc({count, Method, Uri, Status}),
    ets:update_counter(ems_http_metrics,
                       {sum_micros, Method, Uri, Status},
                       round(LatencyMs * 1000),
                       {{sum_micros, Method, Uri, Status}, 0}).

inc_cache_hit()  -> catch inc({cache, hit}),  ok.
inc_cache_miss() -> catch inc({cache, miss}), ok.

%% Level :: error | warn | info | debug
inc_log(Level) -> catch inc({log, Level}), ok.

%% Returns the list of distinct {Method, Uri, Status} label combinations
%% that have been observed so far.
label_sets() ->
    [{M, U, S} || {{M, U, S}} <- ets:tab2list(ems_http_metric_labels)].

%% Reads one counter value; returns 0 if the key has not been seen yet.
get_counter(Key) ->
    case ets:lookup(ems_http_metrics, Key) of
        [{_, V}] -> V;
        []       -> 0
    end.

bucket_defs() -> ?BUCKET_DEFS.


%%====================================================================
%% Internal
%%====================================================================

inc(Key) ->
    ets:update_counter(ems_http_metrics, Key, 1, {Key, 0}).
