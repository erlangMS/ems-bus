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
			{error, Request#request{code = 400, 
									reason = enoent,
								    reason_detail = eclient_name_undefined_error,
									operation = barramento_service_check_client_name,
									response_data = ?ENOENT_JSON}
			};
		AppName ->
			RestAuthUrl = binary_to_list(Conf#config.rest_auth_url),
			case ems_util:oauth2_authenticate_rest_server(RestAuthUrl, Conf#config.rest_user, Conf#config.rest_passwd) of
				{ok, AccessToken} -> 
					case AccessToken of
						undefined -> 
							AuthorizationHeader = [];
						<<>> -> 
							AuthorizationHeader = [];
						_ -> 
							ems_logger:info("ems_barramento_service oauth2 authenticate ~s with user erlangms. AccessToken: ~p.", [RestAuthUrl, AccessToken]),
							AuthorizationHeader = [{"Authorization", "Bearer " ++ binary_to_list(AccessToken)}]
					end,
					UriClient = binary_to_list(Conf#config.rest_base_url) ++ 
								ems_util:url_mask_str(erlang:iolist_to_binary([<<"/auth/client?filter={\"name\":\"">>, AppName, <<"\"}&fields=id,version&limit=1">>])),
					case httpc:request(get, {UriClient, AuthorizationHeader}, [],[]) of
						{ok,{_, _, ClientPayload}} ->
							case ems_util:json_decode_as_map(list_to_binary(ClientPayload)) of
								{ok, []} ->
									ems_logger:info("ems_barramento_service get client ~s from endpoint ~s.", [AppName, UriClient]),
									{error, Request#request{code = 400, 
															reason = eunknow_client,
															response_data = <<"{\"error\": \"eunknow_client\"}"/utf8>>}
									};
								{ok, [ClientParams]} -> 
									ems_logger:info("ems_barramento_service get client ~s from endpoint ~s.", [AppName, UriClient]),
									case maps:is_key(<<"error">>, ClientParams) of
										true -> 
											{error, Request#request{code = 400, 
																	reason = eclient_payload_error,
																	response_data = ?ENOENT_JSON}
											};
										false ->
											ClientId = maps:get(<<"id">>, ClientParams),
											ClientVersion = maps:get(<<"version">>, ClientParams),
											ContentData = iolist_to_binary([<<"{"/utf8>>,
												<<"\"ip\":\""/utf8>>, Conf#config.tcp_listen_main_ip, <<"\","/utf8>>,
												<<"\"base_url\":\""/utf8>>, Conf#config.rest_base_url, <<"\","/utf8>>,
												<<"\"auth_url\":\""/utf8>>, Conf#config.rest_auth_url, <<"\","/utf8>>,
												<<"\"auth_protocol\":\""/utf8>>, atom_to_binary(Conf#config.authorization, utf8), <<"\","/utf8>>,
												<<"\"app_id\":"/utf8>>, integer_to_binary(ClientId), <<","/utf8>>,
												<<"\"app_name\":\""/utf8>>, AppName, <<"\","/utf8>>,
												<<"\"app_version\":\""/utf8>>, ClientVersion, <<"\","/utf8>>,
												<<"\"server_name\":\""/utf8>>, Conf#config.ems_hostname, <<"\","/utf8>>,
												<<"\"environment\":\""/utf8>>, Conf#config.rest_environment, <<"\","/utf8>>,
												<<"\"url_mask\":"/utf8>>, ems_util:boolean_to_binary(Conf#config.rest_url_mask), <<","/utf8>>,
												<<"\"erlangms_version\":\""/utf8>>, list_to_binary(ems_util:version()), <<"\""/utf8>>,
												<<"}"/utf8>>]),
											ExpireDate = ems_util:date_add_minute(Timestamp, ExpiresMinute + 180),
											Expires = cowboy_clock:rfc1123(ExpireDate),
											{ok, Request#request{code = 200,
																 response_header = ResponseHeader#{<<"cache-control">> => CacheControlService,
																								   <<"expires">> => Expires},
																 response_data = ContentData}
											}
									end;
								{error, Reason} -> 						
									ems_logger:error("ems_barramento_service get client ~s from endpoint ~s failed. Reason: ~p", [AppName, UriClient, Reason]),
									{error, Request#request{code = 400, 
															reason = einvalid_decode_client_json,
															operation = json_decode_as_map,
															response_data = <<"{\"error\": \"eget_client_error\"}"/utf8>>}
									}
							end;
						_ -> 
							{error, Request#request{code = 400, 
													reason = einvalid_decode_client_json,
													operation = httpc_request,
													response_data = <<"{\"error\": \"eoauth2_error\"}"/utf8>>}
							}
					end;
				{error, Reason} ->
						{error, Request#request{code = 400, 
												reason = Reason,
												operation = oauth2_authenticate_rest_server,
												response_data = <<"{\"error\": \"eget_token_error\"}"/utf8>>}
						}
			end
	end.

