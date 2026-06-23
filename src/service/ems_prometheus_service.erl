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
        safe_collect(fun collect_vm_metrics/0),
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
                [format_odbc_pool_connections_max(Ds) || Ds <- OdbcDs],
                <<"# HELP db_pool_connections_min Database connection pool minimum size by datasource\n">>,
                <<"# TYPE db_pool_connections_min gauge\n">>,
                [format_odbc_pool_connections_min(Ds) || Ds <- OdbcDs],
                <<"# HELP db_connections_active DB active connections\n">>,
                <<"# TYPE db_connections_active gauge\n">>,
                <<"# HELP db_connections_idle DB idle connections\n">>,
                <<"# TYPE db_connections_idle gauge\n">>,
                <<"# HELP db_connections DB total connections\n">>,
                <<"# TYPE db_connections gauge\n">>,
                [format_db_connections(Ds) || Ds <- OdbcDs],
                <<"# HELP db_connections_max DB max connections\n">>,
                <<"# TYPE db_connections_max gauge\n">>,
                [format_db_connections_max(Ds) || Ds <- OdbcDs],
                <<"# HELP db_connections_min DB min connections\n">>,
                <<"# TYPE db_connections_min gauge\n">>,
                [format_db_connections_min(Ds) || Ds <- OdbcDs],
                <<"# HELP db_connections_pending Pending threads\n">>,
                <<"# TYPE db_connections_pending gauge\n">>,
                <<"# HELP db_connections_timeout_total Connection timeout total count\n">>,
                <<"# TYPE db_connections_timeout_total counter\n">>,
                <<"# HELP db_connections_usage_seconds Connection usage time\n">>,
                <<"# TYPE db_connections_usage_seconds summary\n">>,
                <<"# HELP db_connections_usage_seconds_max Connection usage time\n">>,
                <<"# TYPE db_connections_usage_seconds_max gauge\n">>,
                <<"# HELP db_connections_acquire_seconds Connection acquire time\n">>,
                <<"# TYPE db_connections_acquire_seconds summary\n">>,
                <<"# HELP db_connections_acquire_seconds_max Connection acquire time\n">>,
                <<"# TYPE db_connections_acquire_seconds_max gauge\n">>,
                <<"# HELP db_connections_creation_seconds Connection creation time\n">>,
                <<"# TYPE db_connections_creation_seconds summary\n">>,
                <<"# HELP db_connections_creation_seconds_max Connection creation time\n">>,
                <<"# TYPE db_connections_creation_seconds_max gauge\n">>,
                [format_db_connections_extended(Ds) || Ds <- OdbcDs],
                <<"# HELP jdbc_connections_active JDBC active connections alias\n">>,
                <<"# TYPE jdbc_connections_active gauge\n">>,
                <<"# HELP jdbc_connections_idle JDBC idle connections alias\n">>,
                <<"# TYPE jdbc_connections_idle gauge\n">>,
                <<"# HELP jdbc_connections JDBC total connections alias\n">>,
                <<"# TYPE jdbc_connections gauge\n">>,
                [format_jdbc_connections(Ds) || Ds <- OdbcDs],
                <<"# HELP jdbc_connections_max JDBC max connections alias\n">>,
                <<"# TYPE jdbc_connections_max gauge\n">>,
                [format_jdbc_connections_max(Ds) || Ds <- OdbcDs],
                <<"# HELP jdbc_connections_min JDBC min connections alias\n">>,
                <<"# TYPE jdbc_connections_min gauge\n">>,
                [format_jdbc_connections_min(Ds) || Ds <- OdbcDs]
            ]
    end.

format_odbc_pool_connections(Ds = #service_datasource{id = Id, ds_name = DsName}) ->
    Label        = [{<<"pool">>, DsName}],
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
    Label = [{<<"pool">>, DsName}],
    format_sample(<<"db_pool_connections_max">>, Label, MaxPool).

format_odbc_pool_connections_min(#service_datasource{ds_name = DsName}) ->
    Label = [{<<"pool">>, DsName}],
    format_sample(<<"db_pool_connections_min">>, Label, 0).

format_db_connections(Ds = #service_datasource{id = Id, ds_name = DsName}) ->
    Label        = [{<<"pool">>, DsName}],
    MetricName   = list_to_atom("odbc_pool_count_" ++ integer_to_list(Id)),
    TotalCreated = ems_db:current_counter(MetricName),
    IdleCount    = case catch ems_odbc_pool:connection_pool_size(Ds) of
                       N when is_integer(N) -> N;
                       _                    -> 0
                   end,
    ActiveCount  = max(0, TotalCreated - IdleCount),
    [
        format_sample(<<"db_connections_active">>, Label, ActiveCount),
        format_sample(<<"db_connections_idle">>,   Label, IdleCount),
        format_sample(<<"db_connections">>,        Label, TotalCreated)
    ].

format_db_connections_max(#service_datasource{ds_name = DsName, max_pool_size = MaxPool}) ->
    Label = [{<<"pool">>, DsName}],
    format_sample(<<"db_connections_max">>, Label, MaxPool).

format_db_connections_min(#service_datasource{ds_name = DsName}) ->
    Label = [{<<"pool">>, DsName}],
    format_sample(<<"db_connections_min">>, Label, 0).

format_db_connections_extended(#service_datasource{id = Id, ds_name = DsName}) ->
    Label = [{<<"pool">>, DsName}],
    Pending = get_http_counter({db_pending, Id}),
    Timeout = get_http_counter({db_timeout, Id}),
    
    UsageCount = get_http_counter({db_usage_count, Id}),
    UsageSum = get_http_counter({db_usage_sum, Id}) / 1000000.0,
    UsageMax = get_http_counter({db_usage_max, Id}) / 1000000.0,
    
    AcquireCount = get_http_counter({db_acquire_count, Id}),
    AcquireSum = get_http_counter({db_acquire_sum, Id}) / 1000000.0,
    AcquireMax = get_http_counter({db_acquire_max, Id}) / 1000000.0,
    
    CreationCount = get_http_counter({db_creation_count, Id}),
    CreationSum = get_http_counter({db_creation_sum, Id}) / 1000000.0,
    CreationMax = get_http_counter({db_creation_max, Id}) / 1000000.0,
    
    [
        format_sample(<<"db_connections_pending">>, Label, Pending),
        format_sample(<<"db_connections_timeout_total">>, Label, Timeout),
        format_sample(<<"db_connections_usage_seconds_count">>, Label, UsageCount),
        format_sample_float(<<"db_connections_usage_seconds_sum">>, Label, UsageSum),
        format_sample_float(<<"db_connections_usage_seconds_max">>, Label, UsageMax),
        format_sample(<<"db_connections_acquire_seconds_count">>, Label, AcquireCount),
        format_sample_float(<<"db_connections_acquire_seconds_sum">>, Label, AcquireSum),
        format_sample_float(<<"db_connections_acquire_seconds_max">>, Label, AcquireMax),
        format_sample(<<"db_connections_creation_seconds_count">>, Label, CreationCount),
        format_sample_float(<<"db_connections_creation_seconds_sum">>, Label, CreationSum),
        format_sample_float(<<"db_connections_creation_seconds_max">>, Label, CreationMax)
    ].

get_http_counter(Key) ->
    case catch ets:lookup(ems_http_metrics, Key) of
        [{_, V}] -> V;
        _ -> 0
    end.

format_jdbc_connections(Ds = #service_datasource{id = Id, ds_name = DsName}) ->
    Label        = [{<<"pool">>, DsName}],
    MetricName   = list_to_atom("odbc_pool_count_" ++ integer_to_list(Id)),
    TotalCreated = ems_db:current_counter(MetricName),
    IdleCount    = case catch ems_odbc_pool:connection_pool_size(Ds) of
                       N when is_integer(N) -> N;
                       _                    -> 0
                   end,
    ActiveCount  = max(0, TotalCreated - IdleCount),
    [
        format_sample(<<"jdbc_connections_active">>, Label, ActiveCount),
        format_sample(<<"jdbc_connections_idle">>,   Label, IdleCount),
        format_sample(<<"jdbc_connections">>,        Label, TotalCreated)
    ].

format_jdbc_connections_max(#service_datasource{ds_name = DsName, max_pool_size = MaxPool}) ->
    Label = [{<<"pool">>, DsName}],
    format_sample(<<"jdbc_connections_max">>, Label, MaxPool).

format_jdbc_connections_min(#service_datasource{ds_name = DsName}) ->
    Label = [{<<"pool">>, DsName}],
    format_sample(<<"jdbc_connections_min">>, Label, 0).


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
%% VM Metrics — memory and CPU
%%====================================================================

collect_vm_metrics() ->
    Memory = erlang:memory(),
    Samples = [{[{<<"id">>, atom_to_binary(K, utf8)}], V} || {K, V} <- Memory],
    MemoryMetrics = metric(gauge, <<"jvm_memory_used_bytes">>, <<"The amount of used memory">>, Samples),
    
    ProcessCount = erlang:system_info(process_count),

    CpuMetrics = try
        application:ensure_all_started(os_mon),
        CpuUtil = cpu_sup:util(),
        [
            metric_float(gauge, <<"system_cpu_usage">>, <<"The recent cpu usage for the whole system">>, [{[], CpuUtil / 100.0}])
        ]
    catch _:_ -> []
    end,

    UptimeMs = element(1, erlang:statistics(wall_clock)),
    UptimeSecs = UptimeMs / 1000.0,
    StartTimeSecs = os:system_time(second) - (UptimeMs div 1000),
    UptimeMetric = metric_float(gauge, <<"process_uptime_seconds">>, <<"The uptime of the Erlang process">>, [{[], UptimeSecs}]),
    StartTimeMetric = metric(gauge, <<"process_start_time_seconds">>, <<"Start time of the process since unix epoch">>, [{[], StartTimeSecs}]),

    OpenFiles = case filelib:wildcard("/proc/self/fd/*") of
        [] -> erlang:system_info(port_count);
        FdList -> length(FdList)
    end,
    MaxFiles = erlang:system_info(port_limit),
    OpenFilesMetric = metric(gauge, <<"process_files_open_files">>, <<"The open file descriptor count">>, [{[], OpenFiles}]),
    MaxFilesMetric = metric(gauge, <<"process_files_max_files">>, <<"The maximum file descriptor count">>, [{[], MaxFiles}]),

    ThreadPoolSize = erlang:system_info(thread_pool_size),
    JvmThreadsLive = metric(gauge, <<"jvm_threads_live_threads">>, <<"The current number of live threads">>, [{[], ProcessCount}]),
    JvmThreadsDaemon = metric(gauge, <<"jvm_threads_daemon_threads">>, <<"The current number of daemon threads">>, [{[], ThreadPoolSize}]),

    [
        MemoryMetrics, CpuMetrics,
        UptimeMetric, StartTimeMetric,
        OpenFilesMetric, MaxFilesMetric,
        JvmThreadsLive, JvmThreadsDaemon
    ].


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

metric_float(Type, Name, Help, Samples) ->
    TypeBin = atom_to_binary(Type, utf8),
    Lines   = [format_sample_float(Name, Labels, Value) || {Labels, Value} <- Samples],
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
