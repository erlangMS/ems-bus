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
		 format_alert/1, format_alert/2, format_alert/3
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
			Msg2 = lists:concat(["\033[1;34mDEBUG ", ems_clock:local_time_str(), "  ", Msg, "\033[0m"]),
			io:format(Msg2);
		_ -> ok
	end.

debug2(Msg, Params) -> 
	case in_debug() of
		true -> 
			Msg2 = lists:concat(["\033[1;34mDEBUG ", ems_clock:local_time_str(), "  ", io_lib:format(Msg, Params), "\033[0m"]),
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




%%====================================================================
%% Internal functions
%%====================================================================

write_msg(Tipo, Msg)  ->
	try
		case Tipo of
			info  -> 
				Msg1 = iolist_to_binary([?INFO_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, Msg, <<"\n">>]);
			error -> 
				Msg1 = iolist_to_binary([?ERROR_MESSAGE, ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Msg, ?WHITE_BRK_COLOR]);
			warn  -> 
				Msg1 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Msg, ?WHITE_BRK_COLOR]);
			debug -> 
				Msg1 = iolist_to_binary([?DEBUG_MESSAGE, ?LIGHT_GREEN_COLOR, ems_clock:local_time_str(), ?WHITE_SPACE_COLOR, ?DEBUG_COLOR, Msg, ?WHITE_BRK_COLOR])
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
	
	
do_log_request(Request = #request{rid = RID,
								  req_hash = ReqHash,
								  type = Type,
								  uri = Uri,
								  url = Url,
								  url_masked = UrlMasked,
								  host = Host,
								  version = Version,
								  content_type_in = ContentTypeIn,
								  content_type_out = ContentTypeOut,
								  content_length = ContentLength,
								  accept = Accept,
								  ip_bin = IpBin,
								  payload = Payload,
								  service = Service,
								  params_url = Params,
								  querystring_map = Query,
								  code = Code,
								  reason = Reason,
								  result_cache = ResultCache,
								  result_cache_rid = ResultCacheRid,
								  response_data = ResponseData,
								  authorization = Authorization,
							      cache_control = CacheControl,
								  etag = Etag,
								  if_modified_since = IfModifiedSince,
								  if_none_match = IfNoneMatch,
								  node_exec = Node,
								  referer = Referer,
								  user_agent = UserAgent,
								  user_agent_version = UserAgentVersion,
								  filename = Filename,
								  client = Client,
								  user = User,
								  response_header = ResponseHeader,
								  oauth2_grant_type = GrantType,
								  oauth2_access_token = AccessToken,
								  oauth2_refresh_token = RefreshToken,
								  status_text = StatusText
			  }, 
			  State = #state{log_show_response_max_length = ShowResponseMaxLength, 
							 log_show_payload_max_length = ShowPayloadMaxLength, 
							 log_ult_reqhash = UltReqHash,
							 log_show_response_url_list = ShowResponseUrlList,					
							 log_show_payload_url_list = ShowPayloadUrlList,
							 log_show_content_static_file = LogShowContentStaticFile}) ->
	try
		LogShow = case Service of
						undefined -> true;
						_ -> Service#service.log_show
				  end,
		case LogShow andalso (UltReqHash == undefined orelse UltReqHash =/= ReqHash) of
			true ->
				case Service of
					undefined -> 
						ServiceService = <<>>,
						ServiceName = <<>>,
						ServiceUrl = <<>>,
						ServiceOwner = <<>>,
						ServiceGroup = <<>>,
						ServiceUseRE = <<>>,
						ResultCacheService = 0,
						AuthorizationService = public,
						ShowResponseService = false,
						ShowPayloadService = false,
						ShowResponseHeaderService = false,
						ServiceAuthorizarion = <<>>,
						ServiceRestricted = <<>>,
						OAuth2WithCheckConstraint = <<>>;
					_ ->
						ServiceService = Service#service.service,
						ServiceName = Service#service.name,
						ServiceUrl = Service#service.url,
						ServiceOwner = Service#service.owner,
						ServiceGroup = Service#service.group,
						ServiceUseRE = ems_util:boolean_to_binary(Service#service.use_re),
						ResultCacheService = Service#service.result_cache,
						AuthorizationService = Service#service.authorization,
						ShowResponseService = Service#service.log_show_response,
						ShowPayloadService = Service#service.log_show_payload,
						ShowResponseHeaderService = Service#service.log_show_response_header,
						ServiceAuthorizarion = atom_to_binary(Service#service.authorization, utf8),
						ServiceRestricted = ems_util:boolean_to_binary(Service#service.restricted),
						OAuth2WithCheckConstraint = ems_util:boolean_to_binary(Service#service.oauth2_with_check_constraint)
						
				end,
				TextData = 
					[
					   ?BLUE_COLOR, Type, ?WHITE_SPACE_COLOR, Uri, <<" ">>, atom_to_binary(Version, utf8), <<" ">>,
					   ?TAB_GREEN_COLOR, <<"RID">>, ?WHITE_PARAM_COLOR, integer_to_binary(RID), 
					   ?SPACE_GREEN_COLOR, <<"ReqHash">>, ?WHITE_PARAM_COLOR, integer_to_binary(ReqHash), 
					   case UrlMasked of
							true -> [?TAB_GREEN_COLOR, <<"UrlMasked">>, ?WHITE_PARAM_COLOR, Url];
							false -> <<>>
					   end,
					   ?TAB_GREEN_COLOR, <<"Accept">>, ?WHITE_PARAM_COLOR, Accept,
					   ?TAB_GREEN_COLOR, <<"Content-Type in">>, ?WHITE_PARAM_COLOR, ContentTypeIn, ?SPACE_GREEN_COLOR, <<"out">>, ?WHITE_PARAM_COLOR, ContentTypeOut,
					   ?TAB_GREEN_COLOR, <<"Referer">>, ?WHITE_PARAM_COLOR, 
												case Referer of
													undefined -> <<>>;
													_ -> Referer
												end,
						?TAB_GREEN_COLOR, <<"User-Agent">>, ?WHITE_PARAM_COLOR, ems_util:user_agent_atom_to_binary(UserAgent), ?SPACE_GREEN_COLOR, <<"Version">>, ?SPACE_GREEN_COLOR, ?WHITE_PARAM_COLOR, UserAgentVersion,	?SPACE_GREEN_COLOR, <<"Host">>, ?SPACE_GREEN_COLOR, ?WHITE_PARAM_COLOR, Host, ?SPACE_GREEN_COLOR, <<"Peer">>, ?WHITE_PARAM_COLOR, IpBin, 
						?TAB_GREEN_COLOR, <<"Service name">>, ?WHITE_PARAM_COLOR, ServiceName, ?SPACE_GREEN_COLOR, <<"url">>, ?WHITE_PARAM_COLOR, ServiceUrl, ?SPACE_GREEN_COLOR, <<"Use-RE">>, ?WHITE_PARAM_COLOR, ServiceUseRE,
						?TAB_GREEN_COLOR, <<"Service authorization">>, ?WHITE_PARAM_COLOR, ServiceAuthorizarion, ?SPACE_GREEN_COLOR, <<"restricted">>, ?WHITE_PARAM_COLOR, ServiceRestricted, ?SPACE_GREEN_COLOR, <<"oauth2_with_check_constraint">>, ?WHITE_PARAM_COLOR, OAuth2WithCheckConstraint, 
						?TAB_GREEN_COLOR, <<"Service function">>, ?WHITE_PARAM_COLOR, ServiceService, ?SPACE_GREEN_COLOR, <<"owner">>, ?WHITE_PARAM_COLOR, ServiceOwner, ?SPACE_GREEN_COLOR, <<"group">>, ?WHITE_PARAM_COLOR, ServiceGroup,
						?TAB_GREEN_COLOR, <<"Params">>, ?WHITE_PARAM_COLOR, list_to_binary(io_lib:format("~p", [Params])), 
						?TAB_GREEN_COLOR, <<"Query">>, ?WHITE_PARAM_COLOR, list_to_binary(io_lib:format("~p", [Query])), 
						case ((ShowPayloadService andalso (is_atom(Payload) orelse is_number(Payload))) orelse 
							   (ShowPayloadUrlList =/= [] andalso lists:member(Url, ShowPayloadUrlList)) 
							  ) of
							true ->
							   case ContentLength =< ShowPayloadMaxLength of
									true ->
									     Payload2 = case is_binary(Payload) of
														true -> Payload;
														false -> iolist_to_binary(io_lib:format("~p",[Payload]))
										  		    end,
									     [?TAB_GREEN_COLOR, <<"Payload">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLength), 
									      <<" bytes ">>, ?GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, Payload2, ?WHITE_COLOR,
											 case Reason =/= ok of
												true -> ?RED_COLOR;
												false -> <<>>
											 end]; 
									false -> [?TAB_GREEN_COLOR, <<"Payload">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLength), <<" bytes">>, ?SPACE_GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, <<"large content">>]
								end;
							false -> <<>>
						end,
						case ShowResponseHeaderService of
							true -> [?TAB_GREEN_COLOR, <<"ResponseHeader">>, ?WHITE_PARAM_COLOR, list_to_binary(io_lib:format("~p", [ResponseHeader]))];
							false -> <<>>
						end,
						case (Filename == undefined orelse LogShowContentStaticFile)  
			    andalso 
			     (ShowResponseService orelse
			       (ShowResponseUrlList =/= [] andalso lists:member(Url, ShowResponseUrlList))
			      ) of
							true -> 
								 ResponseData2 = case is_binary(ResponseData) of
													true -> ResponseData;
													false -> iolist_to_binary(io_lib:format("~p",[ResponseData]))
												 end,
								 ContentLengthResponse = byte_size(ResponseData2),
							     case ContentLengthResponse > 0 of
									true ->
										case ContentLengthResponse =< ShowResponseMaxLength of
											true -> [?TAB_GREEN_COLOR, <<"Response">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLengthResponse), 
													 <<" bytes  ">>, ?GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, ResponseData2, ?WHITE_COLOR,
													 case Reason =/= ok of
														true -> ?RED_COLOR;
														false -> <<>>
													 end]; 
											false -> [?TAB_GREEN_COLOR, <<"Response">>, ?WHITE_PARAM_COLOR, integer_to_list(ContentLengthResponse), <<" bytes  ">>, ?GREEN_COLOR, <<"Content">>, ?WHITE_PARAM_COLOR, <<"Large content">>]
										end;
									false -> <<>>
								end;
							 false -> <<>>
						end,
					   case ResultCacheService > 0 of
							true ->
							   ResultCacheSec = trunc(ResultCacheService / 1000),
							   case ResultCacheSec > 0 of 
									true  -> ResultCacheMin = trunc(ResultCacheSec / 60);
									false -> ResultCacheMin = 0
							   end,
							   case ResultCacheMin > 0 of
									true -> 
									   case ResultCache of 
											true ->  [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheMin), <<"min)  ">>, ?WARN_COLOR, <<" <<RID: ">>, integer_to_binary(ResultCacheRid), <<">>">>, ?WHITE_COLOR];
											false -> [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheMin), <<"min)">>] 
										end;
									false ->
									   case ResultCacheSec > 0 of
											true -> 
											   case ResultCache of 
													true ->  [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheSec), <<"sec)  ">>, ?WARN_COLOR, <<" <<RID: ">>, integer_to_binary(ResultCacheRid), <<">>">>, ?WHITE_COLOR];
													false -> [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms (">>, integer_to_binary(ResultCacheSec), <<"sec)">>] 
												end;
											false ->
											   case ResultCache of 
													true ->  [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms ">>, ?WARN_COLOR, <<" <<RID: ">>, integer_to_binary(ResultCacheRid), <<">>">>, ?WHITE_COLOR];
													false -> [?TAB_GREEN_COLOR, <<"Result-Cache">>, ?WHITE_PARAM_COLOR, integer_to_list(ResultCacheService), <<"ms">>]
												end
										end
								end;
							false -> <<>>
						end,
					    ?TAB_GREEN_COLOR, <<"Cache-Control In">>, ?WHITE_PARAM_COLOR, CacheControl,
						?SPACE_GREEN_COLOR, <<"ETag">>, ?WHITE_PARAM_COLOR, case Etag of
											undefined -> <<>>;
											_ -> Etag
										end,
						?TAB_GREEN_COLOR, <<"If-Modified-Since">>, ?WHITE_PARAM_COLOR, case IfModifiedSince of
															undefined -> <<>>;
															_ -> IfModifiedSince
												   end,
					   ?SPACE_GREEN_COLOR, <<"If-None-Match">>, ?WHITE_PARAM_COLOR, case IfNoneMatch of
													undefined -> <<>>;
													_ -> IfNoneMatch
										   end,
					   ?TAB_GREEN_COLOR, <<"Authorization type">>, ?WHITE_PARAM_COLOR, case AuthorizationService of
															basic -> 
																case Authorization of
																	<<>> -> <<"basic, oauth2">>;
																	_ -> <<"oauth2">>
																end;
															oauth2 -> <<"oauth2">>;
															_ -> <<"public">>
													   end,
					   case Authorization of
							<<>> -> <<>>;
							_ -> [?WARN_COLOR, <<" <<">>, Authorization, <<">>">>, ?WHITE_COLOR]
					   end,
					   case GrantType of
									undefined -> <<>>;
									_ -> [?TAB_GREEN_COLOR, <<"OAuth2">>, <<" ">>, ?GREEN_COLOR, <<"grant-type">>, ?WHITE_PARAM_COLOR, GrantType]
					   end,
					   case AccessToken of
							undefined -> <<>>;
							_ ->  [?SPACE_GREEN_COLOR, <<"token">>, ?WHITE_PARAM_COLOR, AccessToken]
					   end,
					   case RefreshToken of
							undefined -> <<>>;
							_ ->  [?SPACE_GREEN_COLOR, <<"refresh token">>, ?WHITE_PARAM_COLOR, RefreshToken]
					   end,
					  ?TAB_GREEN_COLOR, <<"Client">>, ?WHITE_PARAM_COLOR, 
									  case Client of
											public -> <<"public">>;
											undefined -> <<>>;
											_ -> [integer_to_binary(Client#client.id), <<" ">>, Client#client.name]
									   end,
					   ?SPACE_GREEN_COLOR, <<"User">>, ?WHITE_PARAM_COLOR, 
										case User of
											public -> <<"public">>;
											undefined -> <<>>;
											_ ->  [integer_to_binary(User#user.id), <<" ">>,  User#user.login]
										 end,
					   ?TAB_GREEN_COLOR, <<"Node">>, ?WHITE_PARAM_COLOR, 
										case Node of
											undefined -> <<>>;
											_ -> Node
										 end,
					   case Filename of
							undefined -> <<>>;
							_ -> [?TAB_GREEN_COLOR, <<"Filename">>, ?WHITE_PARAM_COLOR, Filename]
						end,
						case Code of
							302 ->  [?TAB_GREEN_COLOR, <<"Redirect-to">>, ?WHITE_PARAM_COLOR, maps:get(<<"location">>, ResponseHeader, <<>>)];
							_ -> <<>>
						end,
					   ?TAB_GREEN_COLOR, <<"Status">>, ?WHITE_PARAM_COLOR, StatusText, <<"\n}">>],
				TextBin = iolist_to_binary(TextData),
				NewState = case Code >= 400 of
								true  -> write_msg(error, TextBin);
								false -> write_msg(info,  TextBin)
							end,
				NewState;
			false -> 
				State
		end
	catch 
		_:ExceptionReason -> 
			format_error("ems_logger do_log_request format invalid message. Reason: ~p.\nRequest: \033[1;31m~p\033[0m\n.", [ExceptionReason, Request]),
			State#state{log_ult_reqhash = ReqHash}
	end.
