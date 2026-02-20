%%********************************************************************
%% @title Module ems_encode_request
%% @version 1.0.0
%% @doc Encodes a cowboy request into an ems_bus request record.
%%      Refactored from ems_util:encode_request_cowboy/3 to improve
%%      maintainability and error granularity.
%% @author ErlangMS Team
%%********************************************************************

-module(ems_encode_request).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([new_from_cowboy_req/3]).

%%====================================================================
%% API
%%====================================================================

-spec new_from_cowboy_req(tuple(), pid(), #encode_request_state{}) -> {ok, #request{}, #service{}, tuple()} | {error, term()}.
new_from_cowboy_req(CowboyReq, WorkerSend, State) ->
    try
        step1_init(CowboyReq, WorkerSend, State)
    catch
        Class:Reason:_ ->
            % Extract simple reason to avoid verbose logging
            SimpleReason = case Reason of
                {error, request, #request{reason = R}, _} -> R;
                _ -> Reason
            end,
            ems_logger:error("ems_encode_request failed. Class: ~p. Reason: ~p.", [Class, SimpleReason]),
            {error, Reason}
    end.

%%====================================================================
%% Internal Steps
%%====================================================================

step1_init(CowboyReq, WorkerSend, State) ->
    RID = erlang:system_time(),
    T1  = trunc(RID / 1.0e6),
    Uri = iolist_to_binary(cowboy_req:uri(CowboyReq)),
    Url = binary_to_list(cowboy_req:path(CowboyReq)),
    
    % Tarpit: Check for malicious URLs and delay response
    case ems_util:check_url_denylist(Url) of
        true ->
            ems_logger:warn("Tarpit: Detected malicious request to ~s from client. Delaying response by ~p ms.", [Url, ?HTTP_TARPIT_DELAY]),
            ems_tarpit:tarpit_hard(),
            % Malicious Request - return 409 Conflict
            Request = #request{
                rid = RID,
                type = cowboy_req:method(CowboyReq),
                url = Url,
                uri = Uri,
                t1 = T1,
                code = ?HTTP_CONFLICT,
                reason = emalicious_request,
                response_data = ?EMALICIOUS_REQUEST_JSON,
                content_type_out = ?CONTENT_TYPE_JSON_UTF8,
                response_header = ?HTTP_HEADERS_DEFAULT,
                latency = ems_util:get_milliseconds() - T1
            },
            erlang:throw({error, request, Request, CowboyReq});
        false ->
            ok
    end,

    % Validate URI length to prevent DoS attacks
    UriSize = byte_size(Uri),
    case UriSize > ?HTTP_MAX_URI_LENGTH of
        true ->
            % URI too long - likely a DoS attack; apply tarpit and return 414
            ems_logger:warn("Tarpit: Detected URI too long (~p bytes) from client. Delaying response by ~p ms.", [UriSize, ?HTTP_TARPIT_DELAY]),
            ems_tarpit:tarpit_hard(),
            Request2 = #request{
                rid = RID,
                type = cowboy_req:method(CowboyReq),
                url = Url,
                uri = Uri,
                t1 = T1,
                code = ?HTTP_URI_TOO_LONG,
                reason = euri_too_long,
                response_data = ?EURI_TOO_LONG_JSON,
                content_type_out = ?CONTENT_TYPE_JSON_UTF8,
                response_header = ?HTTP_HEADERS_DEFAULT,
                latency = ems_util:get_milliseconds() - T1
            },
            erlang:throw({error, request, Request2, CowboyReq});
        false ->
            ok
    end,
    
    step2_parse_url(CowboyReq, WorkerSend, State, Uri, Url, RID, T1).

step2_parse_url(CowboyReq, WorkerSend, State, Uri, Url, RID, T1) ->
    {UrlMasked, UrlSemPrefix, QuerystringBin, QuerystringMap0} = parse_url_logic(Url, CowboyReq),
    Url2 = ems_util:remove_ult_backslash_url(UrlSemPrefix),
    step3_parse_headers(CowboyReq, WorkerSend, State, Uri, Url2, UrlMasked, QuerystringBin, QuerystringMap0, RID, T1).

step3_parse_headers(CowboyReq, WorkerSend, State, Uri, Url2, UrlMasked, QuerystringBin, QuerystringMap0, RID, T1) ->
    Method = cowboy_req:method(CowboyReq),
    
    % Validate HTTP method
    case Method of
        <<"GET">> -> ok;
        <<"POST">> -> ok;
        <<"PUT">> -> ok;
        <<"DELETE">> -> ok;
        <<"OPTIONS">> -> ok;
        <<"HEAD">> -> ok;
        _ -> 
            % Unsupported method - likely a scanner probe; apply tarpit and return 405
            ems_logger:warn("Tarpit: Detected unsupported HTTP method ~s from client. Delaying response by ~p ms.", [Method, ?HTTP_TARPIT_DELAY]),
            ems_tarpit:tarpit_hard(),
            Request = #request{
                rid = RID,
                type = Method,
                url = Url2,
                uri = Uri,
                t1 = T1,
                code = ?HTTP_METHOD_NOT_ALLOWED,
                reason = emethod_not_allowed,
                response_data = ?EMETHOD_NOT_ALLOWED_JSON,
                content_type_out = ?CONTENT_TYPE_JSON_UTF8,
                response_header = ?HTTP_HEADERS_DEFAULT,
                latency = ems_util:get_milliseconds() - T1
            },
            erlang:throw({error, request, Request, CowboyReq})
    end,
    
    {Ip, _} = ems_util:get_real_ip(CowboyReq),
    
    Host = case cowboy_req:header(<<"host">>, CowboyReq) of
        undefined -> cowboy_req:host(CowboyReq);
        H -> H
    end,
    
    Version = cowboy_req:version(CowboyReq),
    ContentTypeIn = parse_content_type_header(cowboy_req:header(<<"content-type">>, CowboyReq)),
    Protocol = parse_protocol(cowboy_req:scheme(CowboyReq)),

    % Validate URL path characters before processing to avoid exceptions in hashsym_and_params
    case ems_util:is_valid_url_path(Url2) of
        false ->
            % Invalid URL - return 400 Bad Request
            LatencyUrlValidation = ems_util:get_milliseconds() - T1,
            RequestUrlValidation = #request{
                rid = RID,
                type = Method,
                url = Url2,
                uri = Uri,
                t1 = T1,
                code = ?HTTP_BAD_REQUEST,
                reason = einvalid_url,
                response_data = ?EINVALID_URL_JSON,
                content_type_out = ?CONTENT_TYPE_JSON_UTF8,
                response_header = ?HTTP_HEADERS_DEFAULT,
                latency = LatencyUrlValidation
            },
            erlang:throw({error, request, RequestUrlValidation, CowboyReq});
        true ->
            ok
    end,
    
    {Rowid, Params_url} = ems_util:hashsym_and_params(Url2),

    UserAgent0 = get_header(<<"user-agent">>, CowboyReq, <<>>),
    UserAgent = UserAgent0,

    % Override URI and Method for healh probe user agents
    {UrlFinal, UriFinal, RowidFinal, ParamsUrlFinal, MethodFinal} = case is_health_probe_user_agent(UserAgent) of
        false -> 
            {Url2, Uri, Rowid, Params_url, Method};
        true -> 
            {RowidZ, ParamsZ} = ems_util:hashsym_and_params("/"),
            {"/", <<"/">>, RowidZ, ParamsZ, <<"GET">>}
    end,

    Request0 = #request{
        rid = RID,
        rowid = RowidFinal,
        type = MethodFinal,
        uri = UriFinal,
        url = UrlFinal,
        url_masked = UrlMasked,
        version = Version,
        content_type_in = ContentTypeIn,
        content_length = 0,
        querystring = QuerystringBin,
        querystring_map = QuerystringMap0,
        params_url = ParamsUrlFinal,
        accept = get_header(<<"accept">>, CowboyReq, <<"*/*">>),
        user_agent = UserAgent,
        accept_encoding = get_header(<<"accept-encoding">>, CowboyReq, <<"*">>),
        cache_control = get_header(<<"cache-control">>, CowboyReq, <<>>),
        authorization = get_header(<<"authorization">>, CowboyReq, <<>>),
        if_modified_since = get_header(<<"if-modified-since">>, CowboyReq, <<>>),
        if_none_match = get_header(<<"if-none-match">>, CowboyReq, <<>>),
        referer = parse_referer_header(CowboyReq),
        ip = Ip,
        host = Host,
        protocol = Protocol,
        result_cache = false,
        t1 = T1,
        payload = <<>>, 
        payload_map = #{},
        response_data = <<>>
    },

    step4_lookup_service(CowboyReq, WorkerSend, State, Request0).

% -----------------------------------------------------------------------------------------------------------------------------------------
% Private functions
% -----------------------------------------------------------------------------------------------------------------------------------------


step4_lookup_service(CowboyReq, WorkerSend, State, Request) ->
    Method = Request#request.type,
    LookupResult = case ems_catalog_lookup:lookup(Request) of
        {_, _, _} = Match -> Match;
        _ -> 
            case Method of 
                <<"OPTIONS">> -> lookup_retry_options(Request, [<<"PUT">>, <<"POST">>, <<"DELETE">>]);
                _ -> false
            end
    end,
    step5_process_lookup(CowboyReq, WorkerSend, State, Request, LookupResult).

step5_process_lookup(CowboyReq, WorkerSend, State, Request, LookupResult) ->
    case LookupResult of
        {Service, ParamsMap, QuerystringMap} -> 
            step6_read_payload(CowboyReq, WorkerSend, State, Request, Service, ParamsMap, QuerystringMap);
        false ->
            handle_enoent(CowboyReq, Request, State)
    end.

step6_read_payload(CowboyReq, _WorkerSend, _State, Request, Service, ParamsMap, QuerystringMap) ->
    
    HttpMaxContentLength = case Service#service.http_max_content_length of
        undefined -> 2097152; % Default 2MB
        Val -> Val
    end,
    
    ContentLength = case cowboy_req:body_length(CowboyReq) of
        undefined -> 0;
        CL -> CL
    end,
    
    if 
        ContentLength > HttpMaxContentLength ->
            % Payload too large - return 413 Payload Too Large
            ems_logger:warn("ems_encode_request: ContentLength ~p exceeds max ~p for ~p ~p", 
                            [ContentLength, HttpMaxContentLength, Request#request.type, Request#request.url]),
            Latency = ems_util:get_milliseconds() - Request#request.t1,
            RequestError = Request#request{
                code = ?HTTP_PAYLOAD_TOO_LARGE,
                reason = epayload_too_large,
                response_data = ?EPAYLOAD_TOO_LARGE_JSON,
                content_type_out = ?CONTENT_TYPE_JSON_UTF8,
                response_header = ?HTTP_HEADERS_DEFAULT,
                latency = Latency
            },
            erlang:throw({error, request, RequestError, CowboyReq});
        true -> ok
    end,

    ReadBodyOpts = #{length => HttpMaxContentLength + 8000, period => 190000, timeout => 180000},
    
    % Use the refactored payload parsing logic
    {ContentTypeIn2, Payload, PayloadMap, QuerystringMap2, CowboyReq2} = 
        case ContentLength > 0 of
            true -> parse_request_payload(Request#request.content_type_in, CowboyReq, ReadBodyOpts, QuerystringMap);
            false -> {Request#request.content_type_in, <<>>, undefined, QuerystringMap, CowboyReq}
        end,
    
    ReqHash = erlang:phash2([Request#request.url, QuerystringMap2, 0, ContentTypeIn2]),
    
    ContentTypeService = Service#service.content_type,
    ContentTypeOut = case ContentTypeService of
        undefined -> ContentTypeIn2;
        _ -> ContentTypeService
    end,

    Request2 = Request#request{
        querystring_map = QuerystringMap2,
        content_type_out = ContentTypeOut,
        content_type_in = ContentTypeIn2,
        content_length = ContentLength,
        payload = Payload,
        payload_map = PayloadMap,
        params_url = ParamsMap,
        req_hash = ReqHash,
        service = Service,
        response_header = ?HTTP_HEADERS_DEFAULT
    },
    
    {ok, Request2, Service, CowboyReq2}.

%%====================================================================
%% Helpers
%%====================================================================

parse_url_logic("/dados/erl.ms/" ++ UrlEncoded, _Req) ->
    decode_masked_url(UrlEncoded);
parse_url_logic("/erl.ms/" ++ UrlEncoded, _Req) ->
    decode_masked_url(UrlEncoded);
parse_url_logic(Url, Req) ->
    UrlSemPrefix = case Url of
        "/dados" ++ Rest -> Rest;
        _ -> Url
    end,
    QuerystringBin = cowboy_req:qs(Req),
    QuerystringMap = case QuerystringBin of
        <<>> -> #{};
        _ -> ems_util:parse_querystring([binary_to_list(QuerystringBin)])
    end,
    {false, UrlSemPrefix, QuerystringBin, QuerystringMap}.

decode_masked_url(UrlEncoded) ->
    Url1 = binary_to_list(base64:decode(UrlEncoded)),
    UrlSemPrefix = case Url1 of
        "/dados" ++ Rest -> Rest;
        _ -> Url1
    end,
    case string:find(UrlSemPrefix, "?") of
        nomatch -> {true, UrlSemPrefix, <<>>, #{}};
        "?" ++ Querystring -> 
            Pos = string:chr(UrlSemPrefix, $?),
            UrlFinal = string:slice(UrlSemPrefix, 0, Pos-1),
            {true, UrlFinal, list_to_binary(Querystring), ems_util:parse_querystring([Querystring])}
    end.

parse_content_type_header(undefined) -> <<>>;
parse_content_type_header(Val) ->
    ValLower = list_to_binary(string:to_lower(binary_to_list(Val))),
    case binary:split(ValLower, <<";">>) of
        [CT|_] -> CT;
        _ -> ValLower
    end.

parse_protocol(<<"http">>) -> http;
parse_protocol(<<"https">>) -> https;
parse_protocol(_) -> erlang:error(einvalid_protocol).

get_header(Name, Req, Default) ->
    case cowboy_req:header(Name, Req) of
        undefined -> Default;
        Val -> Val
    end.

%% Referer header is informational only. ?HTTP_MAX_REFERER_LENGTH bytes is
%% enough to identify the request origin; truncate here so all consumers
%% of request.referer are transparently protected.
parse_referer_header(Req) ->
    case cowboy_req:header(<<"referer">>, Req) of
        undefined -> <<>>;
        Val when byte_size(Val) > ?HTTP_MAX_REFERER_LENGTH -> binary:part(Val, 0, ?HTTP_MAX_REFERER_LENGTH);
        Val -> Val
    end.

handle_enoent(CowboyReq, Request, _State) ->
    ReqHash = erlang:phash2([Request#request.url, Request#request.querystring_map, 0, Request#request.content_type_in]),
    Latency = ems_util:get_milliseconds() - Request#request.t1,
    Options = ?HTTP_HEADERS_DEFAULT,
    DefaultHeaders = ?HTTP_HEADERS_DEFAULT,
    
    {Code, RespData, Headers} = 
        if 
            Request#request.type =:= <<"OPTIONS">> orelse Request#request.type =:= <<"HEAD">> ->
                {200, 
                 ?ENOENT_SERVICE_CONTRACT_JSON,
                 Options};
            true ->
                ems_db:inc_counter(ems_dispatcher_lookup_enoent),
                ems_tarpit:tarpit_leve(),
                {404,
                 ?ENOENT_SERVICE_CONTRACT_JSON,
                 DefaultHeaders}
        end,

    Request2 = Request#request{
        req_hash = ReqHash,
        code = Code,
        reason = enoent_service_contract,
        response_header = Headers,
        response_data = RespData,
        latency = Latency
    },
    
    {error, request, Request2, CowboyReq}.

%% Copied/Moved from ems_util to avoid circular or missing export issues
parse_request_payload(<<"application/json">>, CowboyReq, ReadBodyOpts, QuerystringMap) ->
	{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
	PayloadMap = ems_util:decode_payload_as_json(Payload),
	{<<"application/json">>, Payload, PayloadMap, QuerystringMap, CowboyReq2};

parse_request_payload(<<"application/x-www-form-urlencoded">>, CowboyReq, ReadBodyOpts, QuerystringMap) ->
	{ok, PayloadRaw, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
	case ems_util:detect_payload_is_json(PayloadRaw) of
		true ->
			ems_logger:warn("ems_http_handler sniffed JSON payload despite Content-Type: application/x-www-form-urlencoded. treat as application/json."),
			PayloadMap = ems_util:decode_payload_as_json(PayloadRaw),
			{<<"application/json">>, PayloadRaw, PayloadMap, QuerystringMap, CowboyReq2};
		false ->
			PayloadList = try cow_qs:parse_qs(PayloadRaw)
                          catch
                              _:_ -> 
                                  ems_logger:warn("ems_encode_request: Failed to parse x-www-form-urlencoded payload: ~p", [PayloadRaw]),
                                  []
                          end,
			Payload = PayloadList,
			PayloadMap = maps:from_list(Payload),
			QuerystringMap2 = maps:merge(QuerystringMap, PayloadMap),
			{<<"application/x-www-form-urlencoded">>, Payload, PayloadMap, QuerystringMap2, CowboyReq2}
	end;

parse_request_payload(<<"application/xml">>, CowboyReq, ReadBodyOpts, QuerystringMap) ->
	{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
	PayloadMap = ems_util:decode_payload_as_xml(Payload),
	{<<"application/xml">>, Payload, PayloadMap, QuerystringMap, CowboyReq2};

parse_request_payload(<<"multipart/form-data">>, CowboyReq, _ReadBodyOpts, QuerystringMap) ->
	{ok, Headers, CowboyReq1} = cowboy_req:read_part(CowboyReq),
	io:format("multipart/form-data headers is ~p\n", [Headers]),
	{ok, Payload, CowboyReq2} = cowboy_req:read_part_body(CowboyReq1),								
	{file, <<"inputfile">>, Filename, ContentType} = cow_multipart:form_data(Headers),
	io:format("Received file ~p of content-type ~p as follow:~n~p~n~n", [Filename, ContentType, Payload]),
	{<<"multipart/form-data">>, Payload, undefined, QuerystringMap, CowboyReq2};

parse_request_payload(ContentTypeIn, CowboyReq, ReadBodyOpts, QuerystringMap) ->
	case is_binary_content_type(ContentTypeIn) of
		true ->
			{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
			{ContentTypeIn, Payload, undefined, QuerystringMap, CowboyReq2};
		false ->
			{ok, Payload, CowboyReq2} = cowboy_req:read_body(CowboyReq, ReadBodyOpts),
			case ems_util:detect_payload_is_json(Payload) of
				true ->
					PayloadMap = ems_util:decode_payload_as_json(Payload),
					{<<"application/json">>, Payload, PayloadMap, QuerystringMap, CowboyReq2};
				false ->
					{ContentTypeIn, Payload, undefined, QuerystringMap, CowboyReq2}
			end
	end.

lookup_retry_options(_Request, []) -> false;
lookup_retry_options(Request, [Type|T]) ->
	case ems_catalog_lookup:lookup(Request#request{type = Type}) of
		{Service, ParamsMap, QuerystringMap} -> {Service, ParamsMap, QuerystringMap};
		_ -> lookup_retry_options(Request, T)
	end.

is_binary_content_type(<<"text/plain">>) -> true;
is_binary_content_type(<<"text/csv">>) -> true;
is_binary_content_type(<<"application/octet-stream">>) -> true;
is_binary_content_type(<<"application/gzip">>) -> true;
is_binary_content_type(<<"application/pdf">>) -> true;
is_binary_content_type(<<"application/msword">>) -> true;
is_binary_content_type(<<"application/vnd.openxmlformats-officedocument.wordprocessingml.document">>) -> true;
is_binary_content_type(<<"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet">>) -> true;
is_binary_content_type(<<"image/png">>) -> true;
is_binary_content_type(<<"image/jpeg">>) -> true;
is_binary_content_type(_) -> false.

is_health_probe_user_agent(UserAgent) ->
    case UserAgent of
        <<"Zabbix", _/binary>> -> true;
        <<"kube-probe", _/binary>> -> true;
        _ -> false
    end.
