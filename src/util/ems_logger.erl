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
		 format_info/1, format_info/2, format_info/3,
		 format_warn/1, format_warn/2, format_warn/3,
		 format_error/1, format_error/2, format_error/3
]).


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
			io:put_chars(Msg2);
		_ -> ok
	end.

debug2(Msg, Params) -> 
	case in_debug() of
		true -> 
			Msg2 = lists:concat(["[DEBUG] ", ems_clock:local_time_str(), "  ", io_lib:format(Msg, Params), "\n"]),
			io:put_chars(Msg2);
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


% write direct messages to console

format_info(Message) when is_list(Message) ->	
	format_info(list_to_binary(Message));
format_info(Message) ->	
	Message2 = iolist_to_binary([?INFO_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message, <<"\n">>]),
	io:put_chars(Message2).

format_info(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?INFO_MESSAGE,   ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, Message2, <<"\n">>]),
	io:put_chars(Message3).

format_info(Msg, Params, true) -> format_info(Msg, Params);
format_info(_, _, _) -> ok.


format_warn(Message) when is_list(Message) ->	
	format_warn(list_to_binary(Message));
format_warn(Message) ->	
	Message2 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:put_chars(Message2).

format_warn(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?WARN_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?WARN_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:put_chars(Message3).


format_warn(Msg, Params, true) -> format_warn(Msg, Params);
format_warn(_, _, _) -> ok.


format_error(Message) when is_list(Message) ->	
	format_error(list_to_binary(Message));
format_error(Message) ->	
	Message2 = iolist_to_binary([?ERROR_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Message, ?WHITE_BRK_COLOR]),
	io:put_chars(standard_error, Message2).

format_error(Message, Params) ->	
	Message2 = io_lib:format(Message, Params),
	Message3 = iolist_to_binary([?ERROR_MESSAGE,  ?LIGHT_GREEN_COLOR, ems_util:timestamp_binary(), ?WHITE_SPACE_COLOR, ?RED_COLOR, Message2, ?WHITE_BRK_COLOR]),
	io:put_chars(standard_error, Message3).

format_error(Msg, Params, true) -> format_error(Msg, Params);
format_error(_, _, _) -> ok.







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
			error -> io:put_chars(standard_error, Msg1);
			_ -> io:put_chars(Msg1)
		end
	catch 
		_:ExceptionReason -> 
			format_error("ems_logger write_msg exception. Msg: ~p Reason: ~p.", [Msg, ExceptionReason])
	end.
		
write_msg(Tipo, Msg, Params) ->
	Msg1 = io_lib:format(Msg, Params),
	write_msg(Tipo, Msg1).
