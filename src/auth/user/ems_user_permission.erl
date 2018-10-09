%%********************************************************************
%% @title Module ems_user_permission
%% @version 1.0.0
%% @doc user_permission class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_permission).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([all/0, 
		 find_by_id/1,		 
		 find_by_user/2,
		 find_by_user_and_client/3,
		 find_by_name/1, 
 		 new_from_map/2,
		 get_table/1,
		 find/2,
		 all/1,
		 find_by_hash/1, find_by_hash2/1, make_hash/2, has_grant_permission/3]).


-spec find_by_id(non_neg_integer()) -> {ok, #user_permission{}} | {error, enoent}.
find_by_id(Id) -> 
	case ems_db:get([user_permission_db, user_permission_fs], Id) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.
	
-spec find_by_user(non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user(Id, Fields) -> 
	case ems_db:find([user_permission_db, user_permission_fs], Fields, [{user_id, "==", Id}]) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.
	
-spec find_by_user_and_client(non_neg_integer(), non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user_and_client(Id, ClientId, Fields) -> 
	case ems_db:find([user_permission_db, user_permission_fs], Fields, [{user_id, "==", Id}, {client_id, "==", ClientId}]) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.


-spec all() -> {ok, list()}.
all() -> 
	{ok, ListaUserDb} = ems_db:all(user_permission_db),
	{ok, ListaUserFs} = ems_db:all(user_permission_fs),
	{ok, ListaUserDb ++ ListaUserFs}.
	


-spec find_by_name(binary() | string()) -> {ok, #user_permission{}} | {error, enoent}.
find_by_name(<<>>) -> {error, enoent};
find_by_name("") -> {error, enoent};
find_by_name(undefined) -> {error, enoent};
find_by_name(Name) when is_list(Name) -> 
	find_by_name(list_to_binary(Name));
find_by_name(Name) -> 
	case ems_db:find_first(user_permission_db, [{name, "==", Name}]) of
		{error, enoent} ->
			case ems_db:find_first(user_permission_fs, [{name, "==", Name}]) of
				{error, enoent} -> {error, enoent};
				{ok, Record2} -> {ok, Record2}
			end;
		{ok, Record} -> {ok, Record}
	end.


-spec new_from_map(map(), #config{}) -> {ok, #user_permission{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
		{ok, #user_permission{id = binary_to_integer(maps:get(<<"id">>, Map)),
							  user_id = maps:get(<<"user_id">>, Map),
							  client_id = maps:get(<<"client_id">>, Map),
							  perfil_id = maps:get(<<"perfil_id">>, Map),
							  url = ?UTF8_STRING(maps:get(<<"url">>, Map)),
							  name = ?UTF8_STRING(maps:get(<<"name">>, Map)),
							  grant_get = ems_util:parse_bool(maps:get(<<"grant_get">>, Map, true)),
							  grant_post = ems_util:parse_bool(maps:get(<<"grant_post">>, Map, false)),
							  grant_put = ems_util:parse_bool(maps:get(<<"grant_put">>, Map, false)),
							  grant_delete = ems_util:parse_bool(maps:get(<<"grant_delete">>, Map, false)),
							  position = case maps:get(<<"position">>, Map, 0) of
											undefined -> 0;
											PositionValue -> PositionValue
										 end,
							  ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
							  ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
							  ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
							  ctrl_hash = erlang:phash2(Map),
							  glyphicon = maps:get(<<"glyphicon">>, Map, undefined)
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_permission),
			ems_logger:warn("ems_user parse invalid user_permission specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> user_permission_db | user_permission_fs.
get_table(db) -> user_permission_db;
get_table(fs) -> user_permission_fs.

-spec find(user_permission_fs | user_permission_db, non_neg_integer()) -> {ok, #user_permission{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(user_permission_fs | user_permission_db) -> list() | {error, atom()}.
all(Table) -> ems_db:all(Table).


find_by_hash(Hash) ->
	case mnesia:dirty_index_read(user_permission, Hash, #user_permission.hash) of
		[] -> {error, enoent};
		[Record] -> {ok, Record}
	end.


find_by_hash2(Hash) ->
	case mnesia:dirty_index_read(user_permission, Hash, #user_permission.hash2) of
		[] -> {error, enoent};
		[Record] -> {ok, Record}
	end.

make_hash(Rowid, Id) -> erlang:phash2([Rowid, Id]).

has_grant_permission(#service{oauth2_with_check_constraint = false}, _, _) -> true;
has_grant_permission(#service{oauth2_with_check_constraint = true},
					 #request{rowid = Rowid, type = Type}, 
					 #user{id = Id}) ->
	Hash = make_hash(Rowid, Id),
	case find_by_hash(Hash) of
		{ok, #user_permission{grant_get = GrantGet, 
							  grant_post = GrantPost, 
							  grant_put = GrantPut, 
							  grant_delete = GrantDelete}} ->
			case Type of
				<<"GET">> -> GrantGet == true;
				<<"POST">> -> GrantPost == true;
				<<"PUT">> -> GrantPut == true;
				<<"DELETE">> -> GrantDelete == true
			end;
		_ -> false
	end.

