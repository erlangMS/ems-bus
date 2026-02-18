%%********************************************************************
%% @title Module ems_user_telefone
%% @version 1.0.0
%% @doc user class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_telefone).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([new_from_map/2,
		 get_table/1,
		 find/2]).


-spec new_from_map(map(), #config{}) -> {ok, #user_telefone{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
		{ok, #user_telefone{
					id = maps:get(<<"id">>, Map),
					codigo = maps:get(<<"codigo">>, Map),
					numero = ?UTF8_STRING(maps:get(<<"numero">>, Map)),
					ramal = maps:get(<<"ramal">>, Map),
					ddd = ?UTF8_STRING(maps:get(<<"ddd">>, Map)),
					type = maps:get(<<"type">>, Map),
					ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
					ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
					ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
					ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_telefone),
			ems_logger:warn("ems_user_telefone parse invalid telefone specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_telefone_db | user_telefone_fs.
get_table(db) -> user_telefone_db;
get_table(fs) -> user_telefone_fs.

-spec find(user_telefone_fs | user_telefone_db, non_neg_integer()) -> {ok, #user{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

