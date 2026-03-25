%%********************************************************************
%% @title Module ems_static_file_service
%% @version 1.0.0
%% @doc static files service
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_static_file_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([execute/1]).

execute(Request = #request{service = #service{authorization = _Authorization}, url = Url}) ->	
	Result = ems_util:load_from_file_req(Request),
	case Result of
		{ok, #request{code = Code}} when Code == ?HTTP_OK orelse Code == ?HTTP_NOT_MODIFIED ->
			case Url of
				"/favicon.ico" -> ok;
				"/robots.txt" -> ok;
				"/security.txt" -> ok;
				"/.well-known/security.txt" -> ok;
				_ -> ems_data_loader_ctl:register_activity(auth)
			end;
		_ -> ok
	end,
	Result.
