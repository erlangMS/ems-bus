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

init(CowboyReq, State = #encode_request_state{http_header_options = HttpHeaderOptions}) ->
	case cowboy_req:method(CowboyReq) of
		<<"OPTIONS">> ->
			Response = cowboy_req:reply(200, HttpHeaderOptions, <<>>, CowboyReq),
			{ok, Response, State};
		_ ->
			init_common(CowboyReq, State)
	end.

init_common(CowboyReq, State = #encode_request_state{http_header_default = HttpHeaderDefault,
													debug = Debug}) ->
	case ems_encode_request:new_from_cowboy_req(CowboyReq, self(), State) of
		{ok, Request = #request{t1 = T1}, Service, CowboyReq2} -> 
			case ems_dispatcher:dispatch_request(Request, Service, Debug) of
				{ok, request, Request2 = #request{code = Code0,
												  response_header = ResponseHeader,
												  response_data = ResponseData,
												  content_type_out = ContentTypeOut}} ->
					Code = case Code0 of undefined -> 200; _ -> Code0 end,
					Response = cowboy_req:reply(Code, 
												normalize_headers(ResponseHeader#{<<"content-type">> => ContentTypeOut}, HttpHeaderDefault), 
												ResponseData, 
												CowboyReq2),
					ems_logger:log_request(Request2);
				{error, request, Request2 = #request{code = Code0,
													 response_header = ResponseHeader,
													 response_data = ResponseData}} ->
					Code = case Code0 of undefined -> 500; _ -> Code0 end,
					Response = cowboy_req:reply(Code, 
												normalize_headers(ResponseHeader, HttpHeaderDefault),
												ResponseData, 
												CowboyReq2),
					ems_logger:log_request(Request2);
				{error, Reason} = Error ->
					Request2 = Request#request{code = 400, 
											   content_type_out = ?CONTENT_TYPE_JSON,
											   reason = Reason, 
											   response_data = ems_schema:to_json(Error), 
											   latency = ems_util:get_milliseconds() - T1},
					ResponseHeader = Request2#request.response_header,
					Response = cowboy_req:reply(Request2#request.code, 
												normalize_headers(ResponseHeader, HttpHeaderDefault),
												Request2#request.response_data, CowboyReq2),
					ems_logger:log_request(Request2)
			end;
		{_, request, Request = #request{code = Code0,
									     response_header = ResponseHeader,
									     response_data = ResponseData}, CowboyReq2} ->
			Code = case Code0 of undefined -> 500; _ -> Code0 end,
			Response = cowboy_req:reply(Code, 
										normalize_headers(ResponseHeader, HttpHeaderDefault),
										ResponseData, 
										CowboyReq2),
			ems_logger:log_request(Request);
	{error, Reason} -> 
		Type = binary_to_list(cowboy_req:method(CowboyReq)),
		Url = binary_to_list(cowboy_req:path(CowboyReq)),
		Protocol = binary_to_list(cowboy_req:scheme(CowboyReq)),
		{Ip, _} = cowboy_req:peer(CowboyReq),
		Ip2 = inet_parse:ntoa(Ip),
		% Extract simple reason to avoid verbose logging
		SimpleReason = case Reason of
			{error, request, #request{reason = R}, _} -> R;
			_ -> Reason
		end,
		ems_logger:error("ems_http_handler ~s ~s ~s from ~s. Reason: ~p.", [Type, Url, Protocol, Ip2, SimpleReason]),
		Response = cowboy_req:reply(400, normalize_headers(HttpHeaderDefault, HttpHeaderDefault), ?EINVALID_HTTP_REQUEST, CowboyReq)
	end,
	{ok, Response, State}.

normalize_headers(Headers, DefaultHeaders) ->
	HeadersLower = maps:fold(fun(K, V, Acc) ->
		KeyLower = string:lowercase(K),
		case lists:member(KeyLower, ?HTTP_HEADERS_PROHIBITED_LIST) of
			true -> Acc;
			false -> Acc#{KeyLower => V}
		end
	end, #{}, Headers),
	Merged = maps:merge(DefaultHeaders, HeadersLower),
	Merged.
