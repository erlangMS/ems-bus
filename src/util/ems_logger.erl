-module(ems_logger).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-compile({no_auto_import,[error/2]}).

%% Client API

-export([error/1, error/2, error/3,
		 info/1, info/2, info/3, 
		 warn/1, warn/2, warn/3,
		 debug/1, debug/2, debug/3,
		 debug2/1, debug2/2, debug2/3,
		 in_debug/0, mode_debug/1, 
		 log_request/1, 
		 format_info/1, format_info/2, format_info/3,
		 format_warn/1, format_warn/2, format_warn/3,
		 format_error/1, format_error/2, format_error/3, 
		 format_debug/1, format_debug/2, format_debug/3,
		 format_alert/1, format_alert/2, format_alert/3,
		 set_level/1, show_response/1
]).


%  Armazena o estado do ems_logger para uso local no request_log (simulado)
-record(state, {log_level = info,							% log_level of printable messages
				log_show_response = false,					% show response of request
				log_show_response_max_length,				% show response if content length < show_response_max_length
				log_show_payload = false,					% show payload of request
				log_show_payload_max_length,				% show payload if content length < show_response_max_length
				log_show_response_url_list = [],			% show response if url in 
				log_show_payload_url_list = [],				% show payload if url in 
				log_ult_msg,								% last print message
				log_ult_reqhash, 							% last reqhash of print message
				log_show_content_static_file = false
 			   }). 


%%====================================================================
%% Client API
%%====================================================================
 
error(Msg) -> 
	write_msg(error, Msg).

error(Msg, Params) -> 
	write_msg(error, Msg, Params).

error(Msg, Params, true) -> error(Msg, Params);
error(_, _, _) -> ok.

warn(Msg) -> 
	write_msg(warn, Msg).

warn(Msg, Params) -> 
	write_msg(warn, Msg, Params).

	
warn(Msg, Params, true) -> 	warn(Msg, Params);
warn(_, _, _) -> ok.


info(Msg) -> 
	write_msg(info, Msg).


info(Msg, Params) -> 
	write_msg(info, Msg, Params).


info(Msg, Params, true) -> info(Msg, Params);
info(_, _, _) -> ok.


debug(Msg) -> 
	case in_debug() of
		true -> 
			write_msg(debug, Msg);
		_ -> ok
	end.

debug(Msg, Params) -> 
	case in_debug() of
		true -> 
			write_msg(debug, Msg, Params);
		_ -> ok
	end.
	
debug(Msg, Params, true) -> debug(Msg, Params);
debug(_, _, _) ->  ok.

debug2(Msg) -> 
	case in_debug() of
		true -> 
			Msg2 = lists:concat(["[DEBUG] ", ems_clock:local_time_str(), "  ", Msg, "\n"]),
			io:format(Msg2);
		_ -> ok
	end.

debug2(Msg, Params) -> 
	case in_debug() of
		true -> 
			Msg2 = lists:concat(["[DEBUG] ", ems_clock:local_time_str(), "  ", io_lib:format(Msg, Params), "\n"]),
			io:format(Msg2);
		_ -> ok
	end.

debug2(Msg, Params, true) -> debug2(Msg, Params);
debug2(_, _, _) -> ok.


in_debug() -> ets:lookup(debug_ets, debug) =:= [{debug, true}].

mode_debug(true)  -> 
	info("ems_logger debug mode enabled."),
	ets:insert(debug_ets, {debug, true});
mode_debug(_) -> 
	info("ems_logger debug mode disabled."),
	ets:insert(debug_ets, {debug, false}).

log_request(Request) -> 
	Conf = ems_config:getConfig(),
	State = #state{
		 		   log_show_response = Conf#config.log_show_response,
				   log_show_payload = Conf#config.log_show_payload,
				   log_show_response_max_length = Conf#config.log_show_response_max_length,
 				   log_show_payload_max_length = Conf#config.log_show_payload_max_length,
 				   log_show_content_static_file = Conf#config.log_show_content_static_file},
	do_log_request(Request, State).




% write direct messages to console

format_info(Message) when is_list(Message) ->	
	format_info(list_to_binary(Message));
format_info(Message) ->	
	Message2 = iolist_to_binary([?INFO_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message, <<"\n">>]),
	io:format(Message2).

format_info(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?INFO_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message2, <<"\n">>]),
	io:format(Message3).

format_info(Msg, Params, true) -> format_info(Msg, Params);
format_info(_, _, _) -> ok.


format_warn(Message) when is_list(Message) ->	
	format_warn(list_to_binary(Message));
format_warn(Message) ->	
	Message2 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:format(Message2).

format_warn(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:format(Message3).


format_warn(Msg, Params, true) -> format_warn(Msg, Params);
format_warn(_, _, _) -> ok.


format_error(Message) when is_list(Message) ->	
	format_error(list_to_binary(Message));
format_error(Message) ->	
	Message2 = iolist_to_binary([?ERROR_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:format(standard_error, Message2, []).																							

format_error(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?ERROR_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:format(standard_error, Message3, []).

format_error(Msg, Params, true) -> format_error(Msg, Params);
format_error(_, _, _) -> ok.


format_debug(Message) when is_list(Message) ->	
	format_debug(list_to_binary(Message));
format_debug(Message) ->	
	Message2 = iolist_to_binary([?DEBUG_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?DEBUG_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:format(Message2).

format_debug(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?DEBUG_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?DEBUG_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:format(Message3).

format_debug(Msg, Params, true) -> format_debug(Msg, Params);
format_debug(_, _, _) -> ok.


format_alert(Message) when is_list(Message) ->	
	format_alert(list_to_binary(Message));
format_alert(Message) ->	
	Message2 = iolist_to_binary([?ALERT_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message, <<"\n">>]),
	io:format(Message2).

format_alert(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?ALERT_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message2, <<"\n">>]),
	io:format(Message3).

format_alert(Msg, Params, true) -> format_alert(Msg, Params);
format_alert(_, _, _) -> ok.


set_level(_Level) -> ok.

show_response(_Show) -> ok.




%%====================================================================
%% Internal functions
%%====================================================================

write_msg(Tipo, Msg)  ->
	try
		case Tipo of
			info  -> 
				Msg1 = iolist_to_binary([<<"[">>, ems_clock:local_time_str(), <<"] ">>, ?INFO_MESSAGE,  Msg, <<"\n">>]);
			error -> 
				Msg1 = iolist_to_binary([<<"[">>, ems_clock:local_time_str(), <<"] ">>, ?ERROR_MESSAGE, Msg, <<"\n">>]);
			warn  -> 
				Msg1 = iolist_to_binary([<<"[">>, ems_clock:local_time_str(), <<"] ">>, ?WARN_MESSAGE,  Msg, <<"\n">>]);
			debug -> 
				Msg1 = iolist_to_binary([<<"[">>, ems_clock:local_time_str(), <<"] ">>, ?DEBUG_MESSAGE, Msg, <<"\n">>])
		end,
		case Tipo of
			error -> io:format(standard_error, Msg1, []);
			_ -> io:format(Msg1)
		end
	catch
		_:ReasonException ->
			format_error("ems_logger write_msg exception. Msg: ~p Reason: ~p.", [Msg, ReasonException])
	end.
		
write_msg(Tipo, Msg, Params) ->
	Msg1 = io_lib:format(Msg, Params),
	write_msg(Tipo, Msg1).
	
	
do_log_request(Request = #request{rid = _RID,
								  req_hash = ReqHash,
								  type = Type,
								  uri = Uri,
								  url = _Url,
								  url_masked = _UrlMasked,
								  host = _Host,
								  version = Version,
								  content_type_in = _ContentTypeIn,
								  content_type_out = _ContentTypeOut,
								  content_length = ContentLength,
								  accept = _Accept,
								  ip = Ip,
								  payload = _Payload,
								  service = Service,
								  params_url = _Params,
								  querystring_map = _Query,
								  code = Code,
								  reason = _Reason,
								  result_cache = _ResultCache,
								  result_cache_rid = _ResultCacheRid,
								  response_data = _ResponseData,
								  authorization = _Authorization,
							      cache_control = _CacheControl,
								  etag = _Etag,
								  if_modified_since = _IfModifiedSince,
								  if_none_match = _IfNoneMatch,
							  referer = Referer,
							  user_agent = UserAgent,
							  filename = _Filename,
							  client = _Client,
							  user = User,
							  response_header = _ResponseHeader
			  }, 
			  State = #state{log_show_response_max_length = _ShowResponseMaxLength, 
							 log_show_payload_max_length = _ShowPayloadMaxLength, 
							 log_ult_reqhash = UltReqHash,
							 log_show_response_url_list = _ShowResponseUrlList,					
							 log_show_payload_url_list = _ShowPayloadUrlList,
							 log_show_content_static_file = _LogShowContentStaticFile}) ->
	try
		LogShow = case Service of
						undefined -> true;
						_ -> Service#service.log_show
				  end,
		case LogShow andalso (UltReqHash == undefined orelse UltReqHash =/= ReqHash) of
			true ->
				IpBin = list_to_binary(inet_parse:ntoa(Ip)),
				UserLogin = case User of
								public -> <<"-">>;
								undefined -> <<"-">>;
								_ -> User#user.login
							end,
				
				RefererStr = case Referer of
								undefined -> <<"-">>;
								_ -> Referer
							 end,
				
				UserAgentStr = case UserAgent of
									undefined -> <<"-">>;
									_ -> UserAgent
							   end,

				% Nginx format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
				TextData = [
					IpBin, <<" - ">>, UserLogin, <<" [">>, ems_clock:local_time_str(), <<"] \"">>, 
					Type, <<" ">>, Uri, <<" ">>, atom_to_binary(Version, utf8), <<"\" ">>,
					integer_to_binary(Code), <<" ">>, integer_to_binary(ContentLength), <<" \"">>,
					RefererStr, <<"\" \"">>, UserAgentStr, <<"\"\n">>
				],

				TextBin = iolist_to_binary(TextData),
				% Request logs usually go to stdout (info)
				io:format(TextBin),
				State;
			false -> 
				State
		end
	catch 
		_:ExceptionReason -> 
			format_error("ems_logger do_log_request format invalid message. Reason: ~p.\nRequest: ~p\n.", [ExceptionReason, Request]),
			State#state{log_ult_reqhash = ReqHash}
	end.
