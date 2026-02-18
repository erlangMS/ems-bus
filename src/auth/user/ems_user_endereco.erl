%%********************************************************************
%% @title Module ems_user_endereco
%% @version 1.0.0
%% @doc user class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_endereco).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([new_from_map/2,
		 get_table/1,
		 find/2]).


-spec new_from_map(map(), #config{}) -> {ok, #user_endereco{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
		{ok, #user_endereco{
					id = maps:get(<<"id">>, Map),
					codigo = maps:get(<<"codigo">>, Map),
					endereco = ?UTF8_STRING(maps:get(<<"endereco">>, Map)),
					complemento = ?UTF8_STRING(maps:get(<<"complemento">>, Map)),
					cidade = ?UTF8_STRING(maps:get(<<"cidade">>, Map)),
					bairro = ?UTF8_STRING(maps:get(<<"bairro">>, Map)),
					uf = ?UTF8_STRING(maps:get(<<"uf">>, Map)),
					cep = maps:get(<<"cep">>, Map),
					type = maps:get(<<"type">>, Map),
					ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
					ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
					ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
					ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_endereco),
			ems_logger:warn("ems_user_endereco parse invalid endereco specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_endereco_db | user_endereco_fs.
get_table(db) -> user_endereco_db;
get_table(fs) -> user_endereco_fs.

-spec find(user_endereco_fs | user_endereco_db, non_neg_integer()) -> {ok, #user{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.


