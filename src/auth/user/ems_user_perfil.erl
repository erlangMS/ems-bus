%%********************************************************************
%% @title Module ems_user_perfil
%% @version 1.0.0
%% @doc user_perfil class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_perfil).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([all/0, 
		 find_by_id/1,		 
		 find_by_user_and_client/3,
		 find_by_cpf_and_client/3,
		 find_by_user/2,
		 find_by_name/1, 
 		 new_from_map/2,
		 get_table/1,
		 find/2,
		 all/1]).


-spec find_by_id(non_neg_integer()) -> {ok, #user_perfil{}} | {error, enoent}.
find_by_id(Id) -> 
	case ems_db:get([user_perfil_db, user_perfil_fs], Id) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.

-spec all() -> {ok, list()}.
all() -> 
	{ok, ListaUserDb} = ems_db:all(user_perfil_db),
	{ok, ListaUserFs} = ems_db:all(user_perfil_fs),
	{ok, ListaUserDb ++ ListaUserFs}.


-spec find_by_user(non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user(Id, Fields) -> 
	case ems_db:find([user_perfil_db, user_perfil_fs], Fields, [{user_id, "==", Id}]) of
		{ok, Records} -> {ok, Records};
		_ -> {error, enoent}
	end.


find_by_cpf_and_client(<<>>, _, _) -> {ok, []};
find_by_cpf_and_client(undefined, _, _) -> {ok, []};
find_by_cpf_and_client(Cpf, ClientId, Fields) -> 
	case ems_client:find_by_id(ClientId) of
		{ok, Client} ->
			case ems_db:find(Client#client.scope, [id, remap_user_id], [{cpf, "==", Cpf}]) of
				{ok, ListIdsUserByCpfMap} -> find_by_cpf_and_client_(ListIdsUserByCpfMap, ClientId, Fields, []);
				_ -> {ok, []}
			end;
		{error, enoent} -> {ok, []}
	end.

find_by_cpf_and_client_([], _, _, Result) -> {ok, Result};
find_by_cpf_and_client_([UserByCpfMap|T], ClientId, Fields, Result) ->
	UserId = maps:get(<<"id">>, UserByCpfMap),
	RemapUserId = maps:get(<<"remap_user_id">>, UserByCpfMap),
	case find_by_user_and_client(UserId, ClientId, Fields) of
		{ok, Records} -> 
			Result2 = Result ++ Records;
		_ -> Result2 = Result
	end,
	case RemapUserId  of
		null -> Result3 = Result2;
		undefined -> Result3 = Result2;
		_ ->
			case ems_db:find([user_perfil_db, user_perfil_fs], Fields, [{user_id, "==", RemapUserId}]) of
				{ok, Records2} -> 
					Result3 = Result2 ++ Records2;
				_ -> Result3 = Result2
			end
	end,
	find_by_cpf_and_client_(T, ClientId, Fields, Result3).
	
	
-spec find_by_user_and_client(non_neg_integer(), non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user_and_client(undefined, _, _) -> {ok, []};
find_by_user_and_client(UserId, ClientId, Fields) -> 
	case ems_db:find([user_perfil_db, user_perfil_fs], Fields, [{user_id, "==", UserId}, {client_id, "==", ClientId}]) of
		{ok, Records} -> {ok, Records};
		_ -> {ok, []}
	end.


-spec find_by_name(binary() | string()) -> {ok, #user_perfil{}} | {error, enoent}.
find_by_name(<<>>) -> {error, enoent};
find_by_name("") -> {error, enoent};
find_by_name(undefined) -> {error, enoent};
find_by_name(Name) when is_list(Name) -> 
	find_by_name(list_to_binary(Name));
find_by_name(Name) -> 
	case ems_db:find_first(user_perfil_db, [{name, "==", Name}]) of
		{error, enoent} ->
			case ems_db:find_first(user_perfil_fs, [{name, "==", Name}]) of
				{error, enoent} -> {error, enoent};
				{ok, Record2} -> {ok, Record2}
			end;
		{ok, Record} -> {ok, Record}
	end.


-spec new_from_map(map(), #config{}) -> {ok, #user_perfil{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
		{ok, #user_perfil{id = maps:get(<<"id">>, Map, undefined),
						  perfil_id = maps:get(<<"perfil_id">>, Map, undefined),
						  user_id = maps:get(<<"user_id">>, Map, undefined),
						  client_id = maps:get(<<"client_id">>, Map, undefined),
						  name = ?UTF8_STRING(maps:get(<<"name">>, Map, <<>>)),
						  ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
						  ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
						  ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
						  ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_perfil),
			ems_logger:warn("ems_user parse invalid user_perfil specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_perfil_db | user_perfil_fs.
get_table(db) -> user_perfil_db;
get_table(fs) -> user_perfil_fs.

-spec find(user_perfil_fs | user_perfil_db, non_neg_integer()) -> {ok, #user_perfil{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(user_perfil_fs | user_perfil_db) -> list() | {error, atom()}.
all(Table) -> ems_db:all(Table).

