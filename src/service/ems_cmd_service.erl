%%********************************************************************
%% @title Module ems_cmd_service
%% @version 1.0.0
%% @doc ems_cmd_service
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_cmd_service).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([execute/1]).

execute(Request = #request{service = #service{properties = Properties, content_type = ContentTypeOut}}) ->	
	Script = maps:get(<<"script">>, Properties, []), 
	Result = execute_script(Script, []),
	try
		case ContentTypeOut of
			<<"application/json">> ->
				{ok, Request#request{code = 200, 
									 response_data = ems_schema:to_json({ok, Result})}
				};
			_ -> 
				{ok, Request#request{code = 200, 
									 response_data = Result}
				}
		end
	catch
		_:_ -> 
			ems_logger:error("ems_cmd_service return invalid ~p. Return as text/plain.", [ContentTypeOut]),
			{ok, Request#request{code = 200, 
								 content_type_out = <<"text/plain">>,
								 response_data = Result}
			}
	end.

   
execute_script([], Output) -> 
	try
		iolist_to_binary(lists:reverse(Output))
	catch
		_:Reason -> 
			ems_logger:error("ems_cmd_service exception on convert output to binary. Reason: ~p.", [Reason]),
			<<"">>
	end;
execute_script([H|T], Output) ->
	try
		Cmd = ems_util:replace_config_and_custom_variables(H),
		ems_logger:info("ems_cmd_service \033[0;32mOS Command\033[0m: ~p.", [Cmd]),
		case os:cmd(Cmd, #{ max_size => 8000000 }) of
			"sudo: no tty present and no askpass program specified\n" -> 
				ems_logger:warn("ems_cmd_service cannot capture output."),
				execute_script(T, Output);
			undefined -> 
				ems_logger:warn("ems_cmd_service output is empty."),
				execute_script(T, Output); 
			Result -> 
				Result2 = unicode:characters_to_binary(Result),
				ems_logger:info("ems_cmd_service output: ~p.", [Result2]),
				execute_script(T, [Result2 | Output])
		end
	catch
		_:Reason -> 
			ems_logger:error("ems_cmd_service exception on execute OS command. Reason: ~p.", [Reason]),
			<<"">>
	end.
	
	
	
    
