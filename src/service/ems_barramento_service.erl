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
  
execute(Request) ->
	Conf = ems_config:getConfig(),
	case ems_util:get_param_url(<<"name">>, undefined, Request) of
		undefined ->
			ems_logger:error("ems_barramento_service call failed.\nReason: eclient_name_undefined_error."),
			{error, Request#request{code = ?HTTP_BAD_REQUEST, 
									reason = enoent,
								    reason_detail = eclient_name_undefined_error,
									response_data = ?ENOENT_JSON}
			};
		AppName ->
			case ems_client:find_by_name(AppName) of
				{error, _} ->
					ems_logger:warn("Tarpit: Detected invalid client ~p. Delaying response by ~p ms.", [AppName, ?HTTP_TARPIT_DELAY]),
					timer:sleep(?HTTP_TARPIT_DELAY),
					{error, Request#request{code = ?HTTP_CONFLICT, 
											reason = einvalid_client_barramento,
											response_data = ?EMALICIOUS_REQUEST_JSON}
					};
				{ok, ClientLocal} ->
					ClientId = ClientLocal#client.id,
					ClientVersion = ClientLocal#client.version,
					BaseUrl = case ClientLocal#client.rest_base_url of
						<<>> -> Conf#config.rest_base_url;
						BinaryBaseUrl -> BinaryBaseUrl
					end,
					AuthUrl = case ClientLocal#client.rest_auth_url of
						<<>> -> Conf#config.rest_auth_url;
						BinaryAuthUrl -> BinaryAuthUrl
					end,
					ContentData = iolist_to_binary([<<"{"/utf8>>,
						<<"\"base_url\":\""/utf8>>, BaseUrl, <<"\","/utf8>>,
						<<"\"auth_url\":\""/utf8>>, AuthUrl, <<"\","/utf8>>,
						<<"\"auth_protocol\":\""/utf8>>, atom_to_binary(Conf#config.authorization, utf8), <<"\","/utf8>>,
						<<"\"app_id\":"/utf8>>, integer_to_binary(ClientId), <<","/utf8>>,
						<<"\"app_name\":\""/utf8>>, AppName, <<"\","/utf8>>,
						<<"\"app_version\":\""/utf8>>, ClientVersion, <<"\","/utf8>>,
						<<"\"url_mask\":"/utf8>>, ems_util:boolean_to_binary(Conf#config.rest_url_mask),
						<<"}"/utf8>>]),
					ems_logger:info("ems_barramento_service call for app ~p success.", [AppName]),
					{ok, Request#request{code = ?HTTP_OK,
										 response_data = ContentData}
					}
			end
	end.
