%%********************************************************************
%% @title Module ems_dispatcher
%% @version 1.0.0
%% @doc Responsible for forwarding the requests to services.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_dispatcher).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

%% Client API
-export([dispatch_request/3, dispatch_service_work/3]).


check_result_cache(ReqHash, Worker, Timestamp2, Url, Debug) ->
	case ets:lookup(ets_result_cache_get, ReqHash) of
		[] -> 
			case Debug of
				true -> ems_logger:info("ems_dispatcher result_cache miss (not found). url: ~p", [Url]);
				false -> ok
			end,
			false; 
		[{_, {Timestamp, _, ResultCache, _, _}}] when Timestamp2 - Timestamp > ResultCache -> 
			case Debug of
				true -> ems_logger:info("ems_dispatcher result_cache miss (expired). url: ~p", [Url]);
				false -> ok
			end,
			false;
		[{_, {Timestamp, Request, _, req_done, _}}] ->
			[{post_time, PostTime}] = ets:lookup(ems_dispatcher_post_time, post_time),
			case PostTime < Timestamp of
				true -> {true, Request};
				false -> false
			end;
		[{_, {_, _, _, _, _}}] ->
			% Registration into waiting list is now atomic using duplicate_bag
			ets:insert(ets_result_cache_waiting, {ReqHash, Worker}),
			receive 
				{ReqHash, Result} -> 
					Result
				after 300 -> 
					check_result_cache2(ReqHash, Worker, Timestamp2, 6, Url, Debug)
			end
	end.


check_result_cache2(ReqHash, Worker, Timestamp2, Count, Url, Debug) ->
	case ets:lookup(ets_result_cache_get, ReqHash) of
		[] -> false; 
		[{_, {Timestamp, _, ResultCache, _, _}}] when Timestamp2 - Timestamp > ResultCache -> 
			case Debug of
				true -> ems_logger:info("ems_dispatcher result_cache miss (expired retry). url: ~p", [Url]);
				false -> ok
			end,
			false;
		[{_, {_, Request, _, req_done, _}}] ->
			{true, Request};
		[{_, {_, _, _, req_wait_result, OwnerPid}}] -> 
			% Monitor the process responsible for generating the cache
			MonitorRef = erlang:monitor(process, OwnerPid),
			receive 
				{ReqHash, Result} -> 
					erlang:demonitor(MonitorRef, [flush]),
					Result;
				{'DOWN', MonitorRef, process, OwnerPid, _Reason} -> 
					% The owner process died, so we must assume cache miss and try to execute
					case Debug of
						true -> ems_logger:info("ems_dispatcher result_cache miss (owner died). url: ~p", [Url]);
						false -> ok
					end,
					false
			after 10000 -> 
				erlang:demonitor(MonitorRef, [flush]),
				case Count > 0 of
					true -> check_result_cache2(ReqHash, Worker, Timestamp2, Count - 1, Url, Debug);
					false -> false
				end
			end;
		_ -> false
	end.

notify_workers_waiting_result_cache(ReqHash, RequestDone) ->
	case ets:lookup(ets_result_cache_get, ReqHash) of
		[] -> ok; 
		[{_, {T1, _, ResultCache, _, _}}] ->
			ets:insert(ets_result_cache_get, {ReqHash, {T1, RequestDone, ResultCache, req_done, []}}),
			% Atomically take and clear all waiting workers for this ReqHash
			WorkersWaiting = ets:take(ets_result_cache_waiting, ReqHash),
			notify_workers_waiting_result_cache_(WorkersWaiting, RequestDone, ReqHash) 
	end.

notify_workers_waiting_result_cache_([], _, _) -> ok;
notify_workers_waiting_result_cache_([{_, Worker}|T], RequestDone, ReqHash) ->
	Worker ! {ReqHash, {true, RequestDone}},
	notify_workers_waiting_result_cache_(T, RequestDone, ReqHash).


dispatch_request(Request = #request{req_hash = ReqHash, 
								    ip = Ip,
								    ip_bin = IpBin,
								    type = Type,
								    if_modified_since = IfModifiedSince,
									if_none_match = IfNoneMatch,
								    t1 = T1,
								    worker_send = WorkerSend,
 								    url_masked = UrlMasked, 
									url = Url,
									user_agent = UserAgent
},
				Service = #service{tcp_allowed_address_t = AllowedAddress,
									result_cache = ResultCache},
				Debug) -> 
	try
		case Debug of
			true -> ems_logger:info("ems_dispatcher begin execute. url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin)]);
			false -> ok
		end,
		UserAgentDeniedList = ems_db:get_param(user_agent_denied_list, []),
		case ems_util:allow_user_agent(UserAgent, UserAgentDeniedList) of
			true ->
				case ems_util:allow_ip_address(Ip, AllowedAddress) of
					true ->	
						case ems_auth_user:authenticate(Service, Request) of
							{ok, Client, User, AccessToken, _Scope, _State} -> 	
								case Debug of
									true -> ems_logger:info("ems_dispatcher authenticate ok. url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin)]);
									false -> ok
								end,
								Latency = ems_util:get_milliseconds() - T1,
								Request2 = Request#request{client = Client,
														   user = User,
														   access_token = AccessToken},
								case Type of
									"HEAD" -> 
										{ok, request, Request2#request{code = 200, 
																	   latency = Latency}
										};
									<<"GET">> ->
										case check_result_cache(ReqHash, WorkerSend, T1, Url, Debug) of
											{true, RequestCache} -> 
												case Debug of
													true -> ems_logger:info("ems_dispatcher result_cache hit. url: ~p", [Url]);
													false -> ok
												end,
												ResponseHeader = RequestCache#request.response_header,
												case IfNoneMatch =/= <<>> orelse IfModifiedSince =/= <<>> of
													true ->
														{ok, request, Request2#request{result_cache = true,
																					   code = 304,
																					   reason = enot_modified,
																					   reason_detail = RequestCache#request.reason_detail,
																					   content_type_out = RequestCache#request.content_type_out,
																					   response_data = <<>>,
																					   response_header = ResponseHeader,
																					   result_cache_rid = RequestCache#request.rid,
																					   etag = RequestCache#request.etag,
																					   filename = RequestCache#request.filename,
																					   latency = Latency,
																					   status = req_done}};
													false ->
														{ok, request, Request2#request{result_cache = true,
																						code = RequestCache#request.code,
																						reason = RequestCache#request.reason,
																						reason_detail = RequestCache#request.reason_detail,
																						content_type_out = RequestCache#request.content_type_out,
																						response_data = RequestCache#request.response_data,
																						response_header = ResponseHeader,
																						result_cache_rid = RequestCache#request.rid,
																						etag = RequestCache#request.etag,
																						filename = RequestCache#request.filename,
																						latency = Latency,
																						status = req_done}}
												end;
											false ->
												ems_cache:add(ets_result_cache_get, ResultCache, ReqHash, {T1, Request2, ResultCache, req_wait_result, self()}),
												ResultDispatServiceWork = dispatch_service_work(Request2, Service, Debug),
												case ResultDispatServiceWork of
													{ok, _, _} -> ResultDispatServiceWork; 
													_ -> 
														ems_cache:flush(ets_result_cache_get, ReqHash),
														ResultDispatServiceWork
												end
										end;
									_ -> 
										ResultDispatServiceWork = dispatch_service_work(Request2, Service, Debug),
										ResultDispatServiceWork
								end;
							{error, Reason, ReasonDetail} -> 
								ems_logger:info("ems_dispatcher does not authorize call webservice. url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin)]),
								Latency = ems_util:get_milliseconds() - T1,
								case Type of
									"HEAD" -> 
										{ok, request, Request#request{code = 200, 
																	  latency = Latency}};
									 _ -> 
										% Para finalidades de debug, tenta buscar o user pelo login para armazenar no log
										case ems_util:get_user_request_by_login(Request) of
											{ok, UserFound} -> User = UserFound;
											_ -> User = undefined
										end,
										{error, request, Request#request{code = 400, 
																		 content_type_out = ?CONTENT_TYPE_JSON,
																		 reason = Reason, 
																		 reason_detail = ReasonDetail,
																		 response_data = ems_schema:to_json({error, Reason}), 
																		 user = User,
																		 latency = Latency}}
								end
						end;
					false -> 
						ems_logger:info("ems_dispatcher execute restrict IP to call webservice. url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin)]),
						Latency = ems_util:get_milliseconds() - T1,
						% Para finalidades de debug, tenta buscar o user pelo login para armazenar no log
						case ems_util:get_user_request_by_login(Request) of
							{ok, UserFound} -> User = UserFound;
							_ -> User = undefined
						end,
						{error, request, Request#request{code = 400, 
														 content_type_out = ?CONTENT_TYPE_JSON,
														 reason = access_denied, 
														 reason_detail = host_denied,
														 response_data = ?HOST_DENIED_JSON, 
														 user = User,
														 latency = Latency}}
				end;
			false ->
				ems_logger:info("ems_dispatcher execute restrict User-Agent to call webservice. url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin)]),
				Latency = ems_util:get_milliseconds() - T1,
				RequestUA = Request#request{code = 400, 
										   content_type_out = ?CONTENT_TYPE_JSON,
										   reason = access_denied, 
										   reason_detail = user_agent_denied,
										   response_data = ?ACCESS_DENIED_JSON, 
										   user = undefined,
										   latency = Latency},
				{error, request, RequestUA}
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_dispatcher dispatch_request exception. url_masked: ~p url: ~p  user_agent: ~p IP: ~p Reason: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin), ReasonException]),
			{error, request, Request}
	end.

dispatch_service_work(Request = #request{type = Type,
										  url = Url,
										  ip_bin = IpBin,
										  url_masked = UrlMasked, 
										  user_agent = UserAgent},
					  #service{host = '',
							    module_name = ModuleName,
							    module = Module,
							    function = Function},
 					  Debug) ->
	try
		case Debug of
			true -> ems_logger:info("ems_dispatcher send ~s to service: ~p url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [Type, ModuleName, UrlMasked, Url, UserAgent, binary_to_list(IpBin)]);
			false -> ok
		end,
		%% Retornos possíveis:
		%%
		%% Com processamento de middleware function e result cache
		%% {ok, #request{}}
		%% {error, #request{}}
		%%
		%% Sem processamento de middleware function e result cache
		%% {ok, request, #request{}}
		%% {error, request, #request{}}
		%% {error, atom()}
		case apply(Module, Function, [Request]) of
			{Reason, Request2} ->
				Request3 = Request2#request{reason = case Request2#request.reason of
															undefined -> Reason;
															Reason2 -> Reason2
													   end},
				ResultDispatchMiddleware = dispatch_middleware_function(Request3, Debug),
				ResultDispatchMiddleware;
			Request2 -> 
				Request2
		end
	catch
		_:ReasonException -> 
			ems_logger:error("ems_dispatcher dispatch_service_work_local exception. url_masked: ~p url: ~p  user_agent: ~p IP: ~p Reason: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin), ReasonException]),
			{error, request, Request}
	end;
dispatch_service_work(Request = #request{rid = Rid,
										  type = Type,
										  url = Url,
										  payload = Payload,
										  client = Client,
										  user = User,
										  scope = Scope,
										  access_token = AccessToken,
										  content_type_out = ContentType,  
										  params_url = ParamsMap,
										  querystring_map = QuerystringMap,
										  ip_bin = IpBin,
										  url_masked = UrlMasked, 
										  user_agent = UserAgent},
					  Service = #service{
										 module_name = ModuleName,
										 function_name = FunctionName,
										 metadata = Metadata,
										 timeout = Timeout},
					  Debug) ->
	try
		case erlang:is_tuple(Client) of
			false -> 
				ClientJson = <<"{id:0, codigo:0, name:\"public\", active:true}">>;
			_ -> 
				ClientJson = ems_client:to_json(Client)
		end,
		case erlang:is_tuple(User) of
			false -> 
				UserJson = <<"{id:0, codigo:0, name:\"public\", login:null, email:null, type:null, subtype:null, cpf:null, scope:"", active:true, lista_perfil:{}, lista_permission:{}}">>;
			_ -> 
				case erlang:is_tuple(Client) of
					true -> UserJson = ems_user:to_resource_owner(User, Client#client.id);
					false -> UserJson = ems_user:to_resource_owner(User)
				end
		end,
		T2 = ems_util:get_milliseconds(),
		Msg = {{Rid, Url, binary_to_list(Type), ParamsMap, QuerystringMap, Payload, ContentType, ModuleName, FunctionName, 
				ClientJson, UserJson, Metadata, {Scope, AccessToken}, T2, Timeout}, self()},
		dispatch_service_work_send(Request, Service, Debug, Msg)
	catch
		_:ReasonException -> 
			ems_logger:error("ems_dispatcher dispatch_service_work exception. url_masked: ~p url: ~p  user_agent: ~p IP: ~p Reason: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin), ReasonException]),
			{error, request, Request}
	end.


dispatch_service_work_send(Request = #request{type = Type, 
											  t1 = T1,
											  url_masked = UrlMasked, 
											  url = Url,
											  user_agent = UserAgent,
											  ip_bin = IpBin},
						   Service = #service{host = Host,
							 				  host_name = HostName,
											  module_name = ModuleName,
											  module = Module,
											  timeout = TimeoutService},
						   Debug,
						   Msg) ->
	case ems_node_discovery:get_work_node(Service) of
		{ok, Node} ->
			{Module, Node} ! Msg,
			case Debug of
				true -> 
					ems_logger:info("get_work_node Host ~p  HostName: ~p  ModuleName: ~p", [Host, HostName, ModuleName]),
					ems_logger:info("ems_dispatcher send ~s to Wildfly service: ~p url_masked: ~p url: ~p  user_agent: ~p IP: ~p with timeout ~pms.", [Type, {Module, Node}, UrlMasked, Url, UserAgent, binary_to_list(IpBin), TimeoutService]);
				false -> ok
			end,
			dispatch_service_work_receive(Request, Service, Node, TimeoutService, 0, Debug);
		_Error ->  
			ems_logger:info("ems_dispatcher failed to get work node. url_masked: ~p url: ~p  user_agent: ~p IP: ~p.", [UrlMasked, Url, UserAgent, binary_to_list(IpBin)]),
			Latency = ems_util:get_milliseconds() - T1,
			{error, request, Request#request{code = 400,
											 reason = eunavailable_service,
											 content_type_out = ?CONTENT_TYPE_JSON,
											 response_data = ?EUNAVAILABLE_SERVICE_JSON,
											 latency = Latency}}
	end.
		
dispatch_service_work_receive(Request = #request{rid = Rid, t1 = T1},
							  Service = #service{module = Module,
												 timeout_alert_threshold = TimeoutAlertThreshold},
							  Node,
							  Timeout, TimeoutWaited, Debug) ->
	case TimeoutAlertThreshold of
		0 -> TimeoutWait = Timeout;
		_ -> TimeoutWait = TimeoutAlertThreshold
	end,
	receive 
		{Code, RidRemote, {Reason, ResponseDataReceived}} when RidRemote == Rid  -> 
			ResponseData = case is_binary(ResponseDataReceived) of
				true ->
					case Reason == ok andalso byte_size(ResponseDataReceived) >= 27 of
						true ->
							case ResponseDataReceived of
								% Os dados recebidos do Java pode ser um array de bytes que possui um "header especial" que precisa ser removido do verdadeiro conteúdo
								<<HeaderJavaSerializable:25/binary, _H2:2/binary, DataBin/binary>> -> 
									case HeaderJavaSerializable =:= <<172,237,0,5,117,114,0,2,91,66,172,243,23,248,6,8,84,224,2,0,0,120,112,0,0>> of
										true -> DataBin;
										false -> ResponseDataReceived
									end;
								_ -> ResponseDataReceived
							end;
						false -> ResponseDataReceived
					end;
				false -> 
					case is_list(ResponseDataReceived) of
						true -> 
							try iolist_to_binary(ResponseDataReceived)
							catch _:_ -> list_to_binary(io_lib:format("~p", [ResponseDataReceived]))
							end;
						false when is_atom(ResponseDataReceived) -> atom_to_binary(ResponseDataReceived, utf8);
						false -> list_to_binary(io_lib:format("~p", [ResponseDataReceived]))
					end
			end,
			Request2 = Request#request{code = Code,
									   reason = Reason,
									   response_data = ResponseData},
			dispatch_middleware_function(Request2, Debug);
		_UnknowMessage -> 
			dispatch_service_work_receive(Request, Service, Node, Timeout, TimeoutWaited, Debug)
		after TimeoutWait ->
			TimeoutWaited2 = TimeoutWaited + TimeoutWait,
			Timeout2 = Timeout - TimeoutWait,
			case Timeout2 =< 0 of
				true ->
					case TimeoutAlertThreshold > 0 of
						true -> ems_logger:warn("ems_dispatcher etimeout_service while waiting ~pms for ~p.", [Timeout, {Module, Node}]);
						false -> ok
					end,
					Latency = ems_util:get_milliseconds() - T1,
					{error, request, Request#request{code = 503,
													 reason = etimeout_service,
													 reason_detail = edispatch_service_work_receive_exception,
													 content_type_out = ?CONTENT_TYPE_JSON,
													 response_data = ?ETIMEOUT_SERVICE,
													 latency = Latency}};
				false when TimeoutAlertThreshold > 0 ->
					ems_logger:warn("ems_dispatcher is waiting ~p for more than ~pms.", [{Module, Node}, TimeoutWaited2]),
					dispatch_service_work_receive(Request, Service, Node, Timeout2, TimeoutWaited2, Debug);
				false -> 
					dispatch_service_work_receive(Request, Service, Node, Timeout2, TimeoutWaited2, Debug)
			end
	end.



-spec dispatch_middleware_function(#request{}, boolean()) -> {ok, request, #request{}} | {error, request, #request{}}.
dispatch_middleware_function(Request = #request{reason = ok,
												req_hash = ReqHash,
												t1 = T1,
												type = Type,
												content_length = ContentLength,
												service = #service{middleware = Middleware,
												 				   result_cache = ResultCache}},
							 _Debug) ->
	T3 = ems_util:get_milliseconds(),
	Latency = T3 - T1,
	try
		case Middleware of 
			undefined -> Result = {ok, Request};
			_ ->
				Result = case erlang:function_exported(Middleware, onrequest, 1) of
							true -> apply(Middleware, onrequest, [Request]);
							false -> 
								case code:ensure_loaded(Middleware) of
									{module, _} -> apply(Middleware, onrequest, [Request]);
									_ -> {ok, Request}
								end
						 end
		end,
		case Result of
			{ok, Request2} ->
				case Type =:= <<"GET">> of
					true -> 
						case ResultCache > 0 andalso ContentLength < ?RESULT_CACHE_MAX_SIZE_ENTRY of
							true ->
								Request3 = Request2#request{latency = ems_util:get_milliseconds() - T1,
															status = req_done},
								notify_workers_waiting_result_cache(ReqHash, Request3),
								{ok, request, Request3};
							false -> 
								{ok, request, Request2#request{latency = T3 - T1,
																status = req_done}}
						end;
					false ->
						ets:insert(ems_dispatcher_post_time, {post_time, T3}),
						{ok, request, Request2#request{latency = Latency}}
				end;
			{error, Reason2} = Error ->
				{error, request, Request#request{code = 500,
												 reason = Reason2,
												 content_type_out = ?CONTENT_TYPE_JSON,
												 response_data = ems_schema:to_json(Error),
												 latency = Latency}}
		end
	catch 
		_Exception:Error2 -> 
			{error, request, Request#request{code = 500,
											 reason = Error2,
											 content_type_out = ?CONTENT_TYPE_JSON,
											 response_data = ems_schema:to_json(Error2),
											 latency = Latency}}
	end;
dispatch_middleware_function(Request = #request{t1 = T1, 
											    service = #service{}},
							 _Debug) ->
	T3 = ems_util:get_milliseconds(),
	Latency = T3 - T1,
	{error, request, Request#request{content_type_out = ?CONTENT_TYPE_JSON,
									 latency = Latency}}.

