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


%%====================================================================
%% Service entry point
%%====================================================================

execute(Request) ->
    Output = iolist_to_binary([
        collect_http_histogram(),
        collect_cache_metrics(),
        collect_log_metrics(),
        collect_odbc_pool_metrics(),
        collect_catalog_metrics()
    ]),
    {ok, Request#request{
        code             = 200,
        reason           = ok,
        content_type_out = <<"text/plain; version=0.0.4; charset=utf-8">>,
        response_data    = Output
    }}.


%%====================================================================
%% Histogram — emsbus_http_requests_seconds
%%====================================================================

collect_http_histogram() ->
    LabelSets = ems_http_metrics:label_sets(),
    case LabelSets of
        [] -> [];
        _  ->
            [
                <<"# HELP emsbus_http_requests_seconds HTTP request latency in seconds\n">>,
                <<"# TYPE emsbus_http_requests_seconds histogram\n">>,
                [format_histogram_labels(LS) || LS <- LabelSets]
            ]
    end.

format_histogram_labels({Method, Uri, Status}) ->
    StatusBin   = integer_to_binary(Status),
    BaseLabels  = [{<<"method">>, Method}, {<<"uri">>, Uri}, {<<"status">>, StatusBin}],
    BucketLines = [format_bucket(BaseLabels, Method, Uri, Status, Le, LeBin)
                   || {Le, LeBin} <- ems_http_metrics:bucket_defs()],
    InfCount    = ems_http_metrics:get_counter({bucket, Method, Uri, Status, infinity}),
    Count       = ems_http_metrics:get_counter({count,  Method, Uri, Status}),
    SumMicros   = ems_http_metrics:get_counter({sum_micros, Method, Uri, Status}),
    SumSecs     = SumMicros / 1_000_000,
    [
        BucketLines,
        format_sample(<<"emsbus_http_requests_seconds_bucket">>,
                      BaseLabels ++ [{<<"le">>, <<"+Inf">>}], InfCount),
        format_sample(<<"emsbus_http_requests_seconds_count">>, BaseLabels, Count),
        format_sample_float(<<"emsbus_http_requests_seconds_sum">>,  BaseLabels, SumSecs)
    ].

format_bucket(BaseLabels, Method, Uri, Status, Le, LeBin) ->
    Count = ems_http_metrics:get_counter({bucket, Method, Uri, Status, Le}),
    format_sample(<<"emsbus_http_requests_seconds_bucket">>,
                  BaseLabels ++ [{<<"le">>, LeBin}], Count).


%%====================================================================
%% Cache — emsbus_result_cache_requests_total
%%====================================================================

collect_cache_metrics() ->
    Hit  = ems_http_metrics:get_counter({cache, hit}),
    Miss = ems_http_metrics:get_counter({cache, miss}),
    metric(counter,
           <<"emsbus_result_cache_requests_total">>,
           <<"Total result cache lookups by result">>,
           [
               {[{<<"result">>, <<"hit">>}],  Hit},
               {[{<<"result">>, <<"miss">>}], Miss}
           ]).


%%====================================================================
%% Log events — emsbus_log_events_total
%%====================================================================

collect_log_metrics() ->
    Error = ems_http_metrics:get_counter({log, error}),
    Warn  = ems_http_metrics:get_counter({log, warn}),
    Info  = ems_http_metrics:get_counter({log, info}),
    metric(counter,
           <<"emsbus_log_events_total">>,
           <<"Total log events by level">>,
           [
               {[{<<"level">>, <<"error">>}], Error},
               {[{<<"level">>, <<"warn">>}],  Warn},
               {[{<<"level">>, <<"info">>}],  Info}
           ]).


%%====================================================================
%% ODBC connection pools — emsbus_odbc_pool_connections
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
                    Ds#service_datasource.driver  =/= undefined,
                    Ds#service_datasource.ds_name =/= undefined,
                    is_integer(Ds#service_datasource.max_pool_size),
                    Ds#service_datasource.max_pool_size > 0],
    case OdbcDs of
        [] -> [];
        _  ->
            [
                <<"# HELP emsbus_odbc_pool_connections ODBC connection pool size by datasource and state\n">>,
                <<"# TYPE emsbus_odbc_pool_connections gauge\n">>,
                <<"# HELP emsbus_odbc_pool_connections_max ODBC connection pool maximum size by datasource\n">>,
                <<"# TYPE emsbus_odbc_pool_connections_max gauge\n">>,
                [format_odbc_datasource(Ds) || Ds <- OdbcDs]
            ]
    end.

format_odbc_datasource(Ds = #service_datasource{id = Id,
                                                 ds_name = DsName,
                                                 max_pool_size = MaxPool}) ->
    Label        = [{<<"datasource">>, DsName}],
    MetricName   = list_to_atom("odbc_pool_count_" ++ integer_to_list(Id)),
    TotalCreated = ems_db:current_counter(MetricName),
    IdleCount    = case catch ems_odbc_pool:connection_pool_size(Ds) of
                       N when is_integer(N) -> N;
                       _                    -> 0
                   end,
    ActiveCount  = max(0, TotalCreated - IdleCount),
    [
        format_sample(<<"emsbus_odbc_pool_connections">>,
                      Label ++ [{<<"state">>, <<"active">>}], ActiveCount),
        format_sample(<<"emsbus_odbc_pool_connections">>,
                      Label ++ [{<<"state">>, <<"idle">>}],   IdleCount),
        format_sample(<<"emsbus_odbc_pool_connections_max">>, Label,         MaxPool)
    ].


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

format_sample(Name, [], Value) ->
    iolist_to_binary([Name, <<" ">>, integer_to_binary(Value), <<"\n">>]);
format_sample(Name, Labels, Value) ->
    iolist_to_binary([Name, <<"{">>, format_labels(Labels), <<"} ">>,
                      integer_to_binary(Value), <<"\n">>]).

format_sample_float(Name, Labels, Value) ->
    iolist_to_binary([Name, <<"{">>, format_labels(Labels), <<"} ">>,
                      float_to_binary(Value, [{decimals, 6}]), <<"\n">>]).

format_labels(Labels) ->
    Parts = [iolist_to_binary([K, <<"=\"">>, V, <<"\"">>]) || {K, V} <- Labels],
    iolist_to_binary(lists:join(<<",">>, Parts)).
