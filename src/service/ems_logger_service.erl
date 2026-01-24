%%********************************************************************
%% @title Module ems_logger_service
%% @version 1.0.0
%% @doc ems_logger_service
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_logger_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([check_debug_mode/1, 
		 set_debug_mode/1, 
		 unset_debug_mode/1, 
		 sync/1,
		 set_level_info/1,
		 set_level_error/1,
		 checkpoint/1,
		 show_response/1,
		 hide_response/1,
		 print_info_log/1,
		 print_warn_log/1,
		 print_error_log/1,
		 print_debug_log/1]).

   
check_debug_mode(Request) ->	
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json({ok, ems_logger:in_debug()})}
	}.
    
set_debug_mode(Request) ->	
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json({ok, ems_logger:mode_debug(true)})}
	}.

unset_debug_mode(Request) ->	
	{ok, Request#request{code = 200, 
						 response_data = ems_schema:to_json({ok, ems_logger:mode_debug(false)})}
	}.

sync(Request) ->	
	ems_logger:sync(),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

set_level_info(Request) ->	
	ems_logger:set_level(info),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

set_level_error(Request) ->	
	ems_logger:set_level(error),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

show_response(Request) ->	
	ems_logger:show_response(true),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

hide_response(Request) ->	
	ems_logger:show_response(false),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

checkpoint(Request) ->	
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

print_info_log(Request = #request{payload = Payload}) ->	
	ems_logger:info(Payload),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

print_warn_log(Request = #request{payload = Payload}) ->	
	ems_logger:warn(Payload),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

print_error_log(Request = #request{payload = Payload}) ->	
	ems_logger:error(Payload),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

print_debug_log(Request = #request{payload = Payload}) ->	
	ems_logger:debug(Payload),
	{ok, Request#request{code = 200, 
						 response_data = ?OK_JSON}
	}.

