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
        Class:Reason:Stacktrace ->
            ems_logger:error("ems_encode_request failed. Class: ~p. Reason: ~p. Stack: ~p", [Class, Reason, Stacktrace]),
            {error, Reason}
    end.

%%====================================================================
%% Internal Steps
%%====================================================================

step1_init(CowboyReq, WorkerSend, State) ->
    put(encode_request_cowboy_step, step1_init),
    Uri = iolist_to_binary(cowboy_req:uri(CowboyReq)),
    Url = binary_to_list(cowboy_req:path(CowboyReq)),
    
    % Validate URI length to prevent DoS attacks
    UriSize = byte_size(Uri),
    case UriSize > ?HTTP_MAX_URI_LENGTH of
        true ->
            % URI too long - return 414 URI Too Long
            Latency = ems_util:get_milliseconds() - trunc(erlang:system_time() / 1.0e6),
            Request = #request{
                rid = erlang:system_time(),
                type = cowboy_req:method(CowboyReq),
                url = Url,
                uri = Uri,
                t1 = trunc(erlang:system_time() / 1.0e6),
                code = 414,
                reason = euri_too_long,
                response_data = iolist_to_binary([
                    <<"{\"error\":\"uri_too_long\",\"message\":\"URI length ">>, 
                    integer_to_binary(UriSize), 
                    <<" bytes exceeds maximum allowed ">>, 
                    integer_to_binary(?HTTP_MAX_URI_LENGTH), 
                    <<" bytes\"}">>
                ]),
                content_type_out = <<"application/json; charset=utf-8">>,
                response_header = State#encode_request_state.http_header_default,
                latency = Latency
            },
            erlang:throw({error, request, Request, CowboyReq});
        false ->
            ok
    end,
    
    step2_parse_url(CowboyReq, WorkerSend, State, Uri, Url).

step2_parse_url(CowboyReq, WorkerSend, State, Uri, Url) ->
    put(encode_request_cowboy_step, step2_parse_url),
    {UrlMasked, UrlSemPrefix, QuerystringBin, QuerystringMap0} = parse_url_logic(Url, CowboyReq),
    Url2 = ems_util:remove_ult_backslash_url(UrlSemPrefix),
    step3_parse_headers(CowboyReq, WorkerSend, State, Uri, Url2, UrlMasked, QuerystringBin, QuerystringMap0).

step3_parse_headers(CowboyReq, WorkerSend, State, Uri, Url2, _UrlMasked, QuerystringBin, QuerystringMap0) ->
    put(encode_request_cowboy_step, step3_parse_headers),
    Method = cowboy_req:method(CowboyReq),
    
    % Validate HTTP method to prevent function_clause errors in catalog lookup
    case Method of
        <<"GET">> -> ok;
        <<"POST">> -> ok;
        <<"PUT">> -> ok;
        <<"DELETE">> -> ok;
        <<"OPTIONS">> -> ok;
        <<"HEAD">> -> ok;
        _ -> 
            % Unsupported method - return 405 Method Not Allowed
            Latency = ems_util:get_milliseconds() - trunc(erlang:system_time() / 1.0e6),
            Request = #request{
                rid = erlang:system_time(),
                type = Method,
                url = Url2,
                uri = Uri,
                t1 = trunc(erlang:system_time() / 1.0e6),
                code = 405,
                reason = emethod_not_allowed,
                response_data = iolist_to_binary([<<"{\"error\":\"method_not_allowed\",\"message\":\"HTTP method ">>, Method, <<" is not supported\"}">>]),
                content_type_out = <<"application/json; charset=utf-8">>,
                response_header = State#encode_request_state.http_header_default,
                latency = Latency
            },
            erlang:throw({error, request, Request, CowboyReq})
    end,
    
    {Ip, _} = cowboy_req:peer(CowboyReq),
    IpBin = list_to_binary(inet_parse:ntoa(Ip)),
    
    Host = case cowboy_req:header(<<"host">>, CowboyReq) of
        undefined -> cowboy_req:host(CowboyReq);
        H -> H
    end,
    
    Version = cowboy_req:version(CowboyReq),
    ContentTypeIn = parse_content_type_header(cowboy_req:header(<<"content-type">>, CowboyReq)),
    Protocol = parse_protocol(cowboy_req:scheme(CowboyReq)),
    _Port = cowboy_req:port(CowboyReq),
    
    _HttpHeaderDefault = State#encode_request_state.http_header_default,
    _CurrentNode = State#encode_request_state.current_node,
    
    % Initialize basic Request record
    RID = erlang:system_time(),
    _Timestamp = calendar:local_time(),
    T1 = trunc(RID / 1.0e6),
    {Rowid, Params_url} = ems_util:hashsym_and_params(Url2),

    UserAgent0 = get_header(<<"user-agent">>, CowboyReq, <<>>),
    UserAgent = case byte_size(UserAgent0) > 32 of
        true -> binary:part(UserAgent0, 0, 32);
        false -> UserAgent0
    end,

    Request0 = #request{
        rid = RID,
        rowid = Rowid,
        type = Method,
        uri = Uri,
        url = Url2,
        version = Version,
        content_type_in = ContentTypeIn,
        content_length = 0,
        querystring = QuerystringBin,
        querystring_map = QuerystringMap0,
        params_url = Params_url,
        accept = get_header(<<"accept">>, CowboyReq, <<"*/*">>),
        user_agent = UserAgent,
        accept_encoding = get_header(<<"accept-encoding">>, CowboyReq, <<"*">>),
        cache_control = get_header(<<"cache-control">>, CowboyReq, <<>>),
        authorization = get_header(<<"authorization">>, CowboyReq, <<>>),
        if_modified_since = get_header(<<"if-modified-since">>, CowboyReq, <<>>),
        if_none_match = get_header(<<"if-none-match">>, CowboyReq, <<>>),
        referer = get_header(<<"referer">>, CowboyReq, <<>>),
        forwarded_for = get_header(<<"x-forwarded-for">>, CowboyReq, <<>>),
        ip = Ip,
        ip_bin = IpBin,
        host = Host,
        protocol = Protocol,
        result_cache = false,
        t1 = T1,
        payload = <<>>, 
        payload_map = #{},
        response_data = <<>>
    },

    step4_lookup_service(CowboyReq, WorkerSend, State, Request0).

step4_lookup_service(CowboyReq, WorkerSend, State, Request) ->
    put(encode_request_cowboy_step, step4_lookup_service),
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
    put(encode_request_cowboy_step, step5_process_lookup),
    case LookupResult of
        {Service, ParamsMap, QuerystringMap} -> 
            step6_read_payload(CowboyReq, WorkerSend, State, Request, Service, ParamsMap, QuerystringMap);
        false ->
            handle_enoent(CowboyReq, Request, State)
    end.

step6_read_payload(CowboyReq, _WorkerSend, State, Request, Service, ParamsMap, QuerystringMap) ->
    put(encode_request_cowboy_step, step6_read_payload),
    
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
                code = 413,
                reason = epayload_too_large,
                response_data = iolist_to_binary([
                    <<"{\"error\":\"payload_too_large\",\"message\":\"Content-Length ">>, 
                    integer_to_binary(ContentLength), 
                    <<" bytes exceeds maximum allowed ">>, 
                    integer_to_binary(HttpMaxContentLength), 
                    <<" bytes\"}">>
                ]),
                content_type_out = <<"application/json; charset=utf-8">>,
                response_header = State#encode_request_state.http_header_default,
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
        response_header = State#encode_request_state.http_header_options
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

handle_enoent(CowboyReq, Request, State) ->
    ReqHash = erlang:phash2([Request#request.url, Request#request.querystring_map, 0, Request#request.content_type_in]),
    Latency = ems_util:get_milliseconds() - Request#request.t1,
    Options = State#encode_request_state.http_header_options,
    DefaultHeaders = State#encode_request_state.http_header_default,
    
    {Code, RespData, Headers} = 
        if 
            Request#request.type =:= <<"OPTIONS">> orelse Request#request.type =:= <<"HEAD">> ->
                {200, 
                 ?ENOENT_SERVICE_CONTRACT_JSON,
                 Options};
            true ->
                ems_db:inc_counter(ems_dispatcher_lookup_enoent),
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
