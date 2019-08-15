%%********************************************************************
%% @title Module ems_barramento_service
%% @version 1.0.0
%% @doc Gera o arquivo /sistema/barramento para consulta dos frontends
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************tn************************************************

-module(ems_barramento_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([execute/1]).
  
execute(Request = #request{timestamp = Timestamp,
						   response_header = ResponseHeader,
						   service = #service{cache_control = CacheControlService,
											  expires = ExpiresMinute}}) -> 
	Conf = ems_config:getConfig(),
	case ems_util:get_param_url(<<"name">>, undefined, Request) of
		undefined ->
			ems_logger:error("ems_barramento_service call failed.\nReason: eclient_name_undefined_error."),
			{error, Request#request{code = 400, 
									reason = enoent,
								    reason_detail = eclient_name_undefined_error,
									operation = barramento_service_check_client_name,
									response_data = ?ENOENT_JSON}
			};
		AppName ->
			AuthorizationHeader = [],
			RestBaseAuthUrl = binary_to_list(Conf#config.rest_base_auth_url),
			UrlClient = binary_to_list(erlang:iolist_to_binary([<<"/auth/client?filter={\"name\":\"">>, AppName, <<"\"}&limit=1">>])),
			UriClient = RestBaseAuthUrl ++ UrlClient,
			UriClientMask = RestBaseAuthUrl ++ ems_util:url_mask_str(UrlClient),
			case httpc:request(get, {UriClientMask, AuthorizationHeader}, [],[]) of
				{ok,{_, _, ClientPayload}} ->
					case ems_util:json_decode_as_map(list_to_binary(ClientPayload)) of
						{ok, []} ->
							ems_logger:error("ems_barramento_service call \033[01;34m~p\033[0m failed.\nReason: eunknow_client.", [UriClient]),
							{error, Request#request{code = 400, 
													reason = eunknow_client,
													response_data = <<"{\"error\": \"eunknow_client\"}"/utf8>>}
							};
						{ok, [ClientParams]} -> 
							case maps:is_key(<<"error">>, ClientParams) of
								true -> 
									ems_logger:error("ems_barramento_service call \033[01;34m~p\033[0m failed.\nReason: ~p.", [UriClient, maps:get(<<"error">>, ClientParams)]),
									{error, Request#request{code = 400, 
															reason = eclient_payload_error,
															response_data = ?ENOENT_JSON}
									};
								false ->
									ClientId = maps:get(<<"id">>, ClientParams),
									ClientVersion = maps:get(<<"version">>, ClientParams, <<>>),
									BaseUrl = maps:get(<<"rest_base_url">>, ClientParams, Conf#config.rest_base_url),
									AuthUrl = maps:get(<<"rest_auth_url">>, ClientParams, Conf#config.rest_auth_url),
									ContentData = iolist_to_binary([<<"{"/utf8>>,
										<<"\"base_url\":\""/utf8>>, BaseUrl, <<"\","/utf8>>,
										<<"\"auth_url\":\""/utf8>>, AuthUrl, <<"\","/utf8>>,
										<<"\"auth_protocol\":\""/utf8>>, atom_to_binary(Conf#config.authorization, utf8), <<"\","/utf8>>,
										<<"\"app_id\":"/utf8>>, integer_to_binary(ClientId), <<","/utf8>>,
										<<"\"app_name\":\""/utf8>>, AppName, <<"\","/utf8>>,
										<<"\"app_version\":\""/utf8>>, ClientVersion, <<"\","/utf8>>,
										<<"\"server_name\":\""/utf8>>, Conf#config.ems_hostname, <<"\","/utf8>>,
										<<"\"environment\":\""/utf8>>, Conf#config.rest_environment, <<"\","/utf8>>,
										<<"\"url_mask\":"/utf8>>, ems_util:boolean_to_binary(Conf#config.rest_url_mask), <<","/utf8>>,
										<<"\"erlangms_version\":\""/utf8>>, list_to_binary(ems_util:version()), <<"\""/utf8>>,
										<<"}"/utf8>>]),
									ems_logger:info("ems_barramento_service call \033[01;34m~p\033[0m success.\nContent: \033[01;34m~p\033[0m.", [UriClient, ContentData]),
									case Conf#config.instance_type of
										production ->
											ExpireDate = ems_util:date_add_minute(Timestamp, ExpiresMinute + 180),
											Expires = cowboy_clock:rfc1123(ExpireDate),
											{ok, Request#request{code = 200,
																 response_header = ResponseHeader#{<<"cache-control">> => CacheControlService,
																								   <<"expires">> => Expires},
																 response_data = ContentData}
											};
										_ ->
											{ok, Request#request{code = 200,
																 response_header = ResponseHeader#{<<"cache-control">> => ?CACHE_CONTROL_NO_CACHE},
																 response_data = ContentData}
											}
									end
							end;
						{error, Reason} -> 						
							ems_logger:error("ems_barramento_service call \033[01;34m~p\033[0m failed.\nReason: \033[01;34m~p\033[0m.", [UriClient, Reason]),
							{error, Request#request{code = 400, 
													reason = einvalid_decode_client_json,
													operation = json_decode_as_map,
													response_data = <<"{\"error\": \"eget_client_error\"}"/utf8>>}
							}
					end;
				{error, Reason2} -> 
					ems_logger:error("ems_barramento_service call \033[01;34m~p\033[0m failed.\nReason: \033[01;34m~p\033[0m.", [UriClient, Reason2]),
					{error, Request#request{code = 400, 
											reason = einvalid_decode_client_json,
											operation = httpc_request,
											response_data = <<"{\"error\": \"eoauth2_error\"}"/utf8>>}
					}
			end
	end.

