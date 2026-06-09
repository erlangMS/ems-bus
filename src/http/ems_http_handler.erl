%%********************************************************************
%% @title Module ems_http_server
%% @version 1.0.0
%% @doc Main module HTTP server
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_http_handler).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([init/2]).

init(CowboyReq, State) ->
	{_Ip, _Port} = ems_util:get_real_ip(CowboyReq),
	Conf = ems_config:getConfig(),
	case {cowboy_req:scheme(CowboyReq), Conf#config.force_https} of
		{<<"http">>, true} ->
			Host = cowboy_req:host(CowboyReq),
			Path = cowboy_req:path(CowboyReq),
			Qs = cowboy_req:qs(CowboyReq),
			RedirectUrl = case Qs of
				<<>> -> iolist_to_binary([<<"https://">>, Host, Path]);
				_ -> iolist_to_binary([<<"https://">>, Host, Path, <<"?">>, Qs])
			end,
			ems_logger:info("ems_http_handler redirecting http to https: ~s", [RedirectUrl]),
			Headers = (normalize_headers(?HTTP_HEADERS_DEFAULT, ?HTTP_HEADERS_DEFAULT, CowboyReq))#{<<"location">> => RedirectUrl},
			Response = cowboy_req:reply(307, Headers, <<>>, CowboyReq),
			{ok, Response, State};
		_ ->
			init_rate_limit(CowboyReq, State)
	end.

init_rate_limit(CowboyReq, State) ->
	{Ip, _Port} = ems_util:get_real_ip(CowboyReq),
	case ems_rate_limiter:check(Ip) of
		block ->
			Response = cowboy_req:reply(429, normalize_headers(?HTTP_HEADERS_DEFAULT, ?HTTP_HEADERS_DEFAULT, CowboyReq), ?ERATE_LIMIT_EXCEEDED, CowboyReq),
			{ok, Response, State};
		{tarpit, Delay} ->
			ems_logger:warn("ems_http_handler tarpit delay ~p ms for IP ~s.", [Delay, ems_util:ntoa(Ip)]),
			timer:sleep(Delay),
			case cowboy_req:method(CowboyReq) of
				<<"OPTIONS">> ->
					Response = cowboy_req:reply(200, normalize_headers(?HTTP_HEADERS_DEFAULT, ?HTTP_HEADERS_DEFAULT, CowboyReq), <<>>, CowboyReq),
					{ok, Response, State};
				_ ->
					init_common(CowboyReq, State)
			end;
		allow ->
			case cowboy_req:method(CowboyReq) of
				<<"OPTIONS">> ->
					Response = cowboy_req:reply(200, normalize_headers(?HTTP_HEADERS_DEFAULT, ?HTTP_HEADERS_DEFAULT, CowboyReq), <<>>, CowboyReq),
					{ok, Response, State};
				_ ->
					init_common(CowboyReq, State)
			end
	end.

init_common(CowboyReq, State = #encode_request_state{debug = Debug}) ->
	case ems_encode_request:new_from_cowboy_req(CowboyReq, self(), State) of
		{ok, Request = #request{t1 = T1}, Service, CowboyReq2} -> 
			case ems_dispatcher:dispatch_request(Request, Service, Debug) of
				{ok, request, Request2 = #request{code = Code0,
												  response_header = ResponseHeader,
												  response_data = ResponseData,
												  content_type_out = ContentTypeOut}} ->
					Code = case Code0 of undefined -> 200; _ -> Code0 end,
					_Response = cowboy_req:reply(Code,
												normalize_headers(ResponseHeader#{<<"content-type">> => ContentTypeOut}, ?HTTP_HEADERS_DEFAULT, CowboyReq2),
												ResponseData,
												CowboyReq2),
					ems_http_metrics:observe(Request2#request.type, get_service_url(Request2), Code, Request2#request.latency),
					ok;
				{error, request, Request2 = #request{code = Code0,
													 response_header = ResponseHeader,
													 response_data = ResponseData}} ->
					Code = case Code0 of undefined -> 500; _ -> Code0 end,
					_Response = cowboy_req:reply(Code,
												normalize_headers(ResponseHeader, ?HTTP_HEADERS_DEFAULT, CowboyReq2),
												ResponseData,
												CowboyReq2),
					ems_http_metrics:observe(Request2#request.type, get_service_url(Request2), Code, Request2#request.latency),
					ok;
				{error, Reason} = Error ->
					Request2 = Request#request{code = ?HTTP_BAD_REQUEST, 
											   content_type_out = ?CONTENT_TYPE_JSON,
											   reason = Reason, 
											   response_data = ems_schema:to_json(Error), 
											   latency = ems_util:get_milliseconds() - T1},
					ResponseHeader = Request2#request.response_header,
					_Response = cowboy_req:reply(Request2#request.code, 
												normalize_headers(ResponseHeader, ?HTTP_HEADERS_DEFAULT, CowboyReq2),
												Request2#request.response_data, CowboyReq2),
					ok
			end;
		{_, request, _Request = #request{code = Code0,
									     response_header = ResponseHeader,
									     response_data = ResponseData}, CowboyReq2} ->
			Code = case Code0 of undefined -> 500; _ -> Code0 end,
			_Response = cowboy_req:reply(Code, 
										normalize_headers(ResponseHeader, ?HTTP_HEADERS_DEFAULT, CowboyReq2),
										ResponseData, 
										CowboyReq2),
			ok;
	{error, Reason} -> 
		Type = binary_to_list(cowboy_req:method(CowboyReq)),
		Url = binary_to_list(cowboy_req:path(CowboyReq)),
		Protocol = binary_to_list(cowboy_req:scheme(CowboyReq)),
		{Ip, _} = ems_util:get_real_ip(CowboyReq),

		% Extract simple reason to avoid verbose logging
		case Reason of
			{error, request, #request{code = Code, response_data = ResponseData, response_header = ResponseHeader}, _} ->
				_Response = cowboy_req:reply(Code, normalize_headers(ResponseHeader, ?HTTP_HEADERS_DEFAULT, CowboyReq), ResponseData, CowboyReq),
				ok;
			_ ->
				ems_logger:error("ems_http_handler ~s ~s ~s from ~s. Reason: ~p.", [Type, Url, Protocol, ems_util:ntoa(Ip), Reason]),
				ems_tarpit:tarpit_leve(),
				_Response = cowboy_req:reply(400, normalize_headers(?HTTP_HEADERS_DEFAULT, ?HTTP_HEADERS_DEFAULT, CowboyReq), ?EINVALID_HTTP_REQUEST, CowboyReq)
		end
	end,
	{ok, _Response, State}.

get_service_url(#request{service = S}) when S =/= undefined -> S#service.url;
get_service_url(#request{url = Url}) when Url =/= undefined -> list_to_binary(Url);
get_service_url(_) -> <<"unknown">>.

normalize_headers(Headers, DefaultHeaders, CowboyReq) ->
	% Extract Origin header from request
	Origin = cowboy_req:header(<<"origin">>, CowboyReq, <<>>),
	
	% Validate and set CORS header
	CorsHeader = case ems_util:is_unb_domain(Origin) of
		true -> 
			% Valid domain - allow CORS by echoing the origin
			ems_logger:debug("CORS: Origin ~p allowed by cors_domain configuration.", [Origin]),
			#{<<"access-control-allow-origin">> => Origin};
		false when Origin =:= <<>> ->
			% No Origin header - not a browser request, no CORS header needed
			ems_logger:debug("CORS: No Origin header present, skipping CORS headers."),
			#{};
		false ->
			% Invalid domain - do not set CORS header (browser will block)
			ems_logger:warn("CORS Blocked: Origin ~p is not allowed by cors_domain configuration.", [Origin]),
			#{}
	end,
	
	% Process incoming headers
	HeadersLower = maps:fold(fun(K, V, Acc) ->
		KeyLower = string:lowercase(K),
		case lists:member(KeyLower, ?HTTP_HEADERS_PROHIBITED_LIST) of
			true -> Acc;
			false -> Acc#{KeyLower => V}
		end
	end, #{}, Headers),
	
	% Merge DefaultHeaders and Incoming Headers first
	Merged1 = maps:merge(DefaultHeaders, HeadersLower),

	% Apply the validated CorsHeader (if validation failed, CorsHeader is empty, so no header is sent)
	Merged2 = maps:merge(Merged1, CorsHeader),
	
	% Ensure Content-Type is always present (security requirement - prevents MIME sniffing)
	case maps:is_key(<<"content-type">>, Merged2) of
		true -> Merged2;
		false -> Merged2#{<<"content-type">> => ?CONTENT_TYPE_JSON_UTF8}
	end.
