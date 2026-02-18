%%********************************************************************
%% @title Module ems_user_email
%% @version 1.0.0
%% @doc user class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_email).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([new_from_map/2,
		 get_table/1,
		 find/2]).


-spec new_from_map(map(), #config{}) -> {ok, #user_email{}} | {error, atom()}.
new_from_map(Map, #config{sufixo_email_institucional = SufixoEmailInstitucional}) ->
	try
		Email = ?UTF8_STRING(maps:get(<<"email">>, Map)),
		{ok, #user_email{
					id = maps:get(<<"id">>, Map),
					codigo = maps:get(<<"codigo">>, Map),
					email = Email,
					type = ems_util:check_type_email(SufixoEmailInstitucional, Email),
					ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
					ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
					ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
					ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_email),
			ems_logger:warn("ems_user_email parse invalid email specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_email_db | user_email_fs.
get_table(db) -> user_email_db;
get_table(fs) -> user_email_fs.

-spec find(user_email_fs | user_email_db, non_neg_integer()) -> {ok, #user{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

