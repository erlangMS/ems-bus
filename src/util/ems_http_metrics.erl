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
         observe/5,
         inc_cache_hit/0, inc_cache_miss/0,
         inc_log/1,
         inc_auth_success/0, inc_auth_error/0,
         inc_ldap_success/0, inc_ldap_error/0,
         inc_rate_limit/1,
         inc_tarpit/1,
         label_sets/0,
         get_counter/1,
         bucket_defs/0]).

%% Prometheus histogram bucket thresholds in seconds, paired with their
%% pre-formatted binary labels. Matches the SLO defined for app-forum-api.
-define(BUCKET_DEFS, [
    {0.05, <<"0.05">>},
    {0.1,  <<"0.1">>},
    {0.2,  <<"0.2">>},
    {0.3,  <<"0.3">>},
    {0.5,  <<"0.5">>},
    {1.0,  <<"1.0">>}
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
%%   Exception  :: binary()  — error reason, or <<"None">> on success
%%   LatencyMs  :: integer() — milliseconds from request start to response
%% Wrapped in try/catch: this runs on every request, after the HTTP
%% response has already been sent, so it must never crash the caller.
observe(Method, Uri, Status, Exception, LatencyMs) ->
    try
        LatencySec = LatencyMs / 1000.0,
        Key = {Method, Uri, Status, Exception},
        ets:insert(ems_http_metric_labels, {Key}),
        lists:foreach(fun({Le, _LeBin}) ->
            case LatencySec =< Le of
                true  -> inc({bucket, Method, Uri, Status, Exception, Le});
                false -> ok
            end
        end, ?BUCKET_DEFS),
        inc({bucket, Method, Uri, Status, Exception, infinity}),
        inc({count, Method, Uri, Status, Exception}),
        ets:update_counter(ems_http_metrics,
                           {sum_micros, Method, Uri, Status, Exception},
                           round(LatencyMs * 1000),
                           {{sum_micros, Method, Uri, Status, Exception}, 0}),
        MaxKey = {max_micros, Method, Uri, Status, Exception},
        CurrentMax = get_counter(MaxKey),
        LatencyMicros = round(LatencyMs * 1000),
        if
            LatencyMicros > CurrentMax ->
                ets:insert(ems_http_metrics, {MaxKey, LatencyMicros});
            true -> ok
        end
    catch
        _:_ -> ok
    end.

inc_cache_hit()  -> catch inc({cache, hit}),  ok.
inc_cache_miss() -> catch inc({cache, miss}), ok.

%% Level :: error | warn | info | debug
inc_log(Level) -> catch inc({log, Level}), ok.

%% OAuth2 user authentication outcomes (ems_oauth2_authorize).
inc_auth_success() -> catch inc({auth, success}), ok.
inc_auth_error()   -> catch inc({auth, error}),   ok.

%% LDAP bind outcomes (ems_ldap_handler).
inc_ldap_success() -> catch inc({ldap, success}), ok.
inc_ldap_error()   -> catch inc({ldap, error}),   ok.

%% Action :: tarpit | block (ems_rate_limiter:check/1 result via ems_http_handler).
inc_rate_limit(Action) -> catch inc({rate_limit, Action}), ok.

%% Type :: leve | hard (ems_tarpit:tarpit_leve/0, ems_tarpit:tarpit_hard/0).
inc_tarpit(Type) -> catch inc({tarpit, Type}), ok.

%% Returns the list of distinct {Method, Uri, Status, Exception} label
%% combinations that have been observed so far.
label_sets() ->
    [{M, U, S, E} || {{M, U, S, E}} <- ets:tab2list(ems_http_metric_labels)].

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
