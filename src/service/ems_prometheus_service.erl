%%********************************************************************
%% @title Module ems_prometheus_service
%% @version 1.0.0
%% @doc Exposes RED metrics in Prometheus text format 0.0.4.
%%      Endpoint: GET /metrics
%%      Metrics: HTTP request histogram, result cache, log events,
%%               worker pool saturation, and catalog service count.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_prometheus_service).

-include("include/ems_schema.hrl").

-export([execute/1]).

%% Static label applied to every exposed metric, identifying this
%% application instance to Prometheus/Grafana alongside other services.
-define(APP_LABEL, {<<"application">>, <<"app-ems-bus">>}).


%%====================================================================
%% Service entry point
%%====================================================================

execute(Request) ->
    Output = iolist_to_binary([
        safe_collect(fun collect_http_histogram/0),
        safe_collect(fun collect_cache_metrics/0),
        safe_collect(fun collect_log_metrics/0),
        safe_collect(fun collect_auth_metrics/0),
        safe_collect(fun collect_ldap_metrics/0),
        safe_collect(fun collect_rate_limit_metrics/0),
        safe_collect(fun collect_tarpit_metrics/0),
        safe_collect(fun collect_odbc_pool_metrics/0),
        safe_collect(fun collect_catalog_metrics/0)
    ]),
    {ok, Request#request{
        code             = 200,
        reason           = ok,
        content_type_out = <<"text/plain; version=0.0.4;charset=utf-8">>,
        response_data    = Output
    }}.

%% Isolates each metric family: a failure collecting one (e.g. mnesia or
%% an ETS table unavailable) must not blank out the rest of the scrape.
safe_collect(Fun) ->
    try Fun() catch _:_ -> [] end.


%%====================================================================
%% Histogram — http_server_requests_seconds
%%====================================================================

collect_http_histogram() ->
    LabelSets = ems_http_metrics:label_sets(),
    case LabelSets of
        [] -> [];
        _  ->
            [
                <<"# HELP http_server_requests_seconds HTTP request latency in seconds\n">>,
                <<"# TYPE http_server_requests_seconds histogram\n">>,
                [format_histogram_labels(LS) || LS <- LabelSets],
                <<"# HELP http_server_requests_seconds_max HTTP request maximum latency in seconds\n">>,
                <<"# TYPE http_server_requests_seconds_max gauge\n">>,
                [format_histogram_max(LS) || LS <- LabelSets]
            ]
    end.

format_histogram_labels({Method, Uri, Status, Exception}) ->
    StatusBin   = integer_to_binary(Status),
    Outcome     = status_to_outcome(Status),
    BaseLabels  = [{<<"method">>, Method}, {<<"uri">>, Uri}, {<<"status">>, StatusBin}, {<<"exception">>, Exception}, {<<"outcome">>, Outcome}],
    BucketLines = [format_bucket(BaseLabels, Method, Uri, Status, Exception, Le, LeBin)
                   || {Le, LeBin} <- ems_http_metrics:bucket_defs()],
    InfCount    = ems_http_metrics:get_counter({bucket, Method, Uri, Status, Exception, infinity}),
    Count       = ems_http_metrics:get_counter({count,  Method, Uri, Status, Exception}),
    SumMicros   = ems_http_metrics:get_counter({sum_micros, Method, Uri, Status, Exception}),
    SumSecs     = SumMicros / 1_000_000,
    [
        BucketLines,
        format_sample(<<"http_server_requests_seconds_bucket">>,
                      BaseLabels ++ [{<<"le">>, <<"+Inf">>}], InfCount),
        format_sample(<<"http_server_requests_seconds_count">>, BaseLabels, Count),
        format_sample_float(<<"http_server_requests_seconds_sum">>,  BaseLabels, SumSecs)
    ].

format_bucket(BaseLabels, Method, Uri, Status, Exception, Le, LeBin) ->
    Count = ems_http_metrics:get_counter({bucket, Method, Uri, Status, Exception, Le}),
    format_sample(<<"http_server_requests_seconds_bucket">>,
                  BaseLabels ++ [{<<"le">>, LeBin}], Count).

format_histogram_max({Method, Uri, Status, Exception}) ->
    StatusBin   = integer_to_binary(Status),
    Outcome     = status_to_outcome(Status),
    BaseLabels  = [{<<"method">>, Method}, {<<"uri">>, Uri}, {<<"status">>, StatusBin}, {<<"exception">>, Exception}, {<<"outcome">>, Outcome}],
    MaxMicros   = ems_http_metrics:get_counter({max_micros, Method, Uri, Status, Exception}),
    MaxSecs     = MaxMicros / 1_000_000,
    format_sample_float(<<"http_server_requests_seconds_max">>, BaseLabels, MaxSecs).

status_to_outcome(Status) when Status >= 200, Status < 300 -> <<"SUCCESS">>;
status_to_outcome(Status) when Status >= 400, Status < 500 -> <<"CLIENT_ERROR">>;
status_to_outcome(Status) when Status >= 500, Status < 600 -> <<"SERVER_ERROR">>;
status_to_outcome(Status) when Status >= 300, Status < 400 -> <<"REDIRECTION">>;
status_to_outcome(Status) when Status >= 100, Status < 200 -> <<"INFORMATIONAL">>;
status_to_outcome(_) -> <<"UNKNOWN">>.


%%====================================================================
%% Cache — cache_requests_total
%%====================================================================

collect_cache_metrics() ->
    Hit  = ems_http_metrics:get_counter({cache, hit}),
    Miss = ems_http_metrics:get_counter({cache, miss}),
    metric(counter,
           <<"cache_requests_total">>,
           <<"Total result cache lookups by result">>,
           [
               {[{<<"result">>, <<"hit">>}],  Hit},
               {[{<<"result">>, <<"miss">>}], Miss}
           ]).


%%====================================================================
%% Log events — logback_events_total
%%====================================================================

collect_log_metrics() ->
    Error = ems_http_metrics:get_counter({log, error}),
    Warn  = ems_http_metrics:get_counter({log, warn}),
    Info  = ems_http_metrics:get_counter({log, info}),
    metric(counter,
           <<"logback_events_total">>,
           <<"Total log events by level">>,
           [
               {[{<<"level">>, <<"error">>}], Error},
               {[{<<"level">>, <<"warn">>}],  Warn},
               {[{<<"level">>, <<"info">>}],  Info}
           ]).


%%====================================================================
%% OAuth2 — auth_user_success_total / auth_user_error_total
%%====================================================================

collect_auth_metrics() ->
    Success = ems_http_metrics:get_counter({auth, success}),
    Error   = ems_http_metrics:get_counter({auth, error}),
    [
        metric(counter, <<"auth_user_success_total">>, <<"Total successful OAuth2 user authentications">>, [{[], Success}]),
        metric(counter, <<"auth_user_error_total">>,   <<"Total failed OAuth2 user authentications">>,     [{[], Error}])
    ].


%%====================================================================
%% LDAP — ldap_user_success_total / ldap_user_error_total
%%====================================================================

collect_ldap_metrics() ->
    Success = ems_http_metrics:get_counter({ldap, success}),
    Error   = ems_http_metrics:get_counter({ldap, error}),
    [
        metric(counter, <<"ldap_user_success_total">>, <<"Total successful LDAP user authentications">>, [{[], Success}]),
        metric(counter, <<"ldap_user_error_total">>,   <<"Total failed LDAP user authentications">>,     [{[], Error}])
    ].


%%====================================================================
%% Rate limiter — rate_limit_total
%%====================================================================

collect_rate_limit_metrics() ->
    Tarpit = ems_http_metrics:get_counter({rate_limit, tarpit}),
    Block  = ems_http_metrics:get_counter({rate_limit, block}),
    metric(counter,
           <<"rate_limit_total">>,
           <<"Total requests throttled by the rate limiter, by action">>,
           [
               {[{<<"action">>, <<"tarpit">>}], Tarpit},
               {[{<<"action">>, <<"block">>}],  Block}
           ]).


%%====================================================================
%% Tarpit — tarpit_total
%%====================================================================

collect_tarpit_metrics() ->
    Leve = ems_http_metrics:get_counter({tarpit, leve}),
    Hard = ems_http_metrics:get_counter({tarpit, hard}),
    metric(counter,
           <<"tarpit_total">>,
           <<"Total requests delayed by the tarpit defense mechanism, by severity">>,
           [
               {[{<<"type">>, <<"leve">>}], Leve},
               {[{<<"type">>, <<"hard">>}], Hard}
           ]).


%%====================================================================
%% ODBC connection pools — db_pool_connections
%%====================================================================

%% Iterates all datasources registered in Mnesia and reports active,
%% idle, and max connections — equivalent to HikariCP pool metrics.
%%
%% active = total live connections (Mnesia counter) - idle queue length
%% idle   = connections in the pool queue, ready to reuse
%% max    = max_pool_size configured for the datasource
collect_odbc_pool_metrics() ->
    Datasources = try
        Keys = mnesia:dirty_all_keys(service_datasource),
        lists:filtermap(fun(K) ->
            case mnesia:dirty_read(service_datasource, K) of
                [Ds] -> {true, Ds};
                _    -> false
            end
        end, Keys)
    catch _:_ -> []
    end,
    OdbcDs = [Ds || Ds <- Datasources,
                    lists:member(Ds#service_datasource.type, [postgresql, sqlserver]),
                    Ds#service_datasource.ds_name =/= undefined,
                    is_integer(Ds#service_datasource.max_pool_size),
                    Ds#service_datasource.max_pool_size > 0],
    case OdbcDs of
        [] -> [];
        _  ->
            [
                <<"# HELP db_pool_connections Database connection pool size by datasource and state\n">>,
                <<"# TYPE db_pool_connections gauge\n">>,
                [format_odbc_pool_connections(Ds) || Ds <- OdbcDs],
                <<"# HELP db_pool_connections_max Database connection pool maximum size by datasource\n">>,
                <<"# TYPE db_pool_connections_max gauge\n">>,
                [format_odbc_pool_connections_max(Ds) || Ds <- OdbcDs]
            ]
    end.

format_odbc_pool_connections(Ds = #service_datasource{id = Id, ds_name = DsName}) ->
    Label        = [{<<"datasource">>, DsName}],
    MetricName   = list_to_atom("odbc_pool_count_" ++ integer_to_list(Id)),
    TotalCreated = ems_db:current_counter(MetricName),
    IdleCount    = case catch ems_odbc_pool:connection_pool_size(Ds) of
                       N when is_integer(N) -> N;
                       _                    -> 0
                   end,
    ActiveCount  = max(0, TotalCreated - IdleCount),
    [
        format_sample(<<"db_pool_connections">>,
                      Label ++ [{<<"state">>, <<"active">>}], ActiveCount),
        format_sample(<<"db_pool_connections">>,
                      Label ++ [{<<"state">>, <<"idle">>}],   IdleCount),
        format_sample(<<"db_pool_connections">>,
                      Label ++ [{<<"state">>, <<"total">>}],  TotalCreated)
    ].

format_odbc_pool_connections_max(#service_datasource{ds_name = DsName, max_pool_size = MaxPool}) ->
    Label = [{<<"datasource">>, DsName}],
    format_sample(<<"db_pool_connections_max">>, Label, MaxPool).


%%====================================================================
%% Catalog — emsbus_catalog_services_total
%%====================================================================

collect_catalog_metrics() ->
    Methods = [
        {<<"GET">>,    ets_catalog_get_fs},
        {<<"POST">>,   ets_catalog_post_fs},
        {<<"PUT">>,    ets_catalog_put_fs},
        {<<"DELETE">>, ets_catalog_delete_fs},
        {<<"KERNEL">>, ets_catalog_kernel_fs}
    ],
    Samples = [{[{<<"method">>, M}], safe_ets_size(T)} || {M, T} <- Methods],
    metric(gauge,
           <<"emsbus_catalog_services_total">>,
           <<"Number of registered services by HTTP method">>,
           Samples).

safe_ets_size(Table) ->
    try ets:info(Table, size) catch _:_ -> 0 end.


%%====================================================================
%% Formatting helpers
%%====================================================================

metric(Type, Name, Help, Samples) ->
    TypeBin = atom_to_binary(Type, utf8),
    Lines   = [format_sample(Name, Labels, Value) || {Labels, Value} <- Samples],
    iolist_to_binary([
        <<"# HELP ">>, Name, <<" ">>, Help, <<"\n">>,
        <<"# TYPE ">>, Name, <<" ">>, TypeBin, <<"\n">>
        | Lines
    ]).

format_sample(Name, Labels, Value) ->
    iolist_to_binary([Name, <<"{">>, format_labels([?APP_LABEL | Labels]), <<"} ">>,
                      integer_to_binary(Value), <<"\n">>]).

format_sample_float(Name, Labels, Value) ->
    iolist_to_binary([Name, <<"{">>, format_labels([?APP_LABEL | Labels]), <<"} ">>,
                      float_to_binary(Value, [{decimals, 6}]), <<"\n">>]).

format_labels(Labels) ->
    Parts = [iolist_to_binary([K, <<"=\"">>, V, <<"\"">>]) || {K, V} <- Labels],
    iolist_to_binary(lists:join(<<",">>, Parts)).
