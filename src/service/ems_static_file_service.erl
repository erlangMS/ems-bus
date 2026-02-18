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

execute(Request) ->	
	ems_data_loader_ctl:register_activity(auth),
	ems_util:load_from_file_req(Request).
   
    
