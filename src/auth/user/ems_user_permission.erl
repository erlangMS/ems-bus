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
		 find_by_user/1, find_by_user/2,
		 find_by_user_and_client/2, find_by_user_and_client/3,
		 find_by_cpf_and_client/3,
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
	case ems_db:find([user_permission_db, user_permission_fs], Fields, [{'or', [{user_id, "==", Id}, {user_id, "==", 0}]}]) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.

-spec find_by_user(non_neg_integer()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user(Id) -> find_by_user(Id, []).

	
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
	case RemapUserId of
		null -> Result3 = Result2;
		undefined -> Result3 = Result2;
		_ ->
			case find_by_user_and_client(RemapUserId, ClientId, Fields) of
				{ok, Records2} -> 
					Result3 = Result2 ++ Records2;
				_ -> Result3 = Result2
			end
	end,
	find_by_cpf_and_client_(T, ClientId, Fields, Result3).
	
	
-spec find_by_user_and_client(non_neg_integer(), non_neg_integer(), list()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user_and_client(undefined, _, _) -> {ok, []};
find_by_user_and_client(Id, ClientId, Fields) -> 
	case ems_db:find([user_permission_db, user_permission_fs], Fields, [ {'or', [{user_id, "==", Id}, {user_id, "==", 0}]}, {'or', [{client_id, "==", ClientId}, {client_id, "==", 0}]}]) of
		{ok, Record} -> {ok, Record};
		_ -> {ok, []}
	end.

-spec find_by_user_and_client(non_neg_integer(), non_neg_integer()) -> {ok, list(#user_perfil{})} | {error, enoent}.
find_by_user_and_client(Id, ClientId) -> find_by_user_and_client(Id, ClientId, []).

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
		put(parse_step, id),
		Id = ems_util:parse_to_integer(maps:get(<<"id">>, Map)),
	
		put(parse_step, user_id),
		UserId = ems_util:parse_to_integer(maps:get(<<"user_id">>, Map, 0)),
	
		put(parse_step, client_id),
		ClientId = ems_util:parse_to_integer(maps:get(<<"client_id">>, Map, 0)),
	
		put(parse_step, perfil_id),
		PerfilId = ems_util:parse_to_integer(maps:get(<<"perfil_id">>, Map, 0)),
	
		put(parse_step, url),
		Url = ?UTF8_STRING(maps:get(<<"url">>, Map)),
	
		put(parse_step, name),
		Name = ?UTF8_STRING(maps:get(<<"name">>, Map)),
	
		put(parse_step, grant_get),
		GrantGet = ems_util:parse_bool(maps:get(<<"grant_get">>, Map, true)),
	
		put(parse_step, grant_post),
		GrantPost = ems_util:parse_bool(maps:get(<<"grant_post">>, Map, false)),

		put(parse_step, grant_put),
		GrantPut = ems_util:parse_bool(maps:get(<<"grant_put">>, Map, false)),
		
		put(parse_step, grant_delete),
		GrantDelete = ems_util:parse_bool(maps:get(<<"grant_delete">>, Map, false)),

		put(parse_step, position),
		Position = case ems_util:parse_to_integer(maps:get(<<"position">>, Map, 0)) of
						undefined -> 0;
						PositionValue -> PositionValue
					end,

		put(parse_step, ctrl_path),
		CtrlPath = maps:get(<<"ctrl_path">>, Map, <<>>),

		put(parse_step, ctrl_file),
		CtrlFile = maps:get(<<"ctrl_file">>, Map, <<>>),

		put(parse_step, ctrl_modified),
		CtrlModified = maps:get(<<"ctrl_modified">>, Map, undefined),

		put(parse_step, glyphicon),
		Glyphicon = maps:get(<<"glyphicon">>, Map, undefined),

		put(parse_step, ctrl_hash),
		CtrlHash = erlang:phash2(Map),

		{ok, #user_permission{id = Id,
							  user_id = UserId,
							  client_id = ClientId, 
							  perfil_id = PerfilId, 
							  url = Url, 
							  name = Name, 
							  grant_get = GrantGet,
							  grant_post = GrantPost,
							  grant_put = GrantPut,
							  grant_delete = GrantDelete,
							  position = Position,
							  ctrl_path = CtrlPath,
							  ctrl_file = CtrlFile, 
							  ctrl_modified = CtrlModified, 
							  ctrl_hash = CtrlHash,
							  glyphicon = Glyphicon
			}
		}
	catch
		_Exception:Reason -> 
			ems_db:inc_counter(edata_loader_invalid_user_permission),
			ems_logger:warn("ems_user parse invalid user_permission on field ~p specification: ~p\n\t~p.\n", [get(parse_step), Reason, Map]),
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
	case mnesia:dirty_index_read([user_permission_db, user_permission_fs], Hash, #user_permission.hash) of
		[] -> {error, enoent};
		[Record] -> {ok, Record}
	end.


find_by_hash2(Hash) ->
	case mnesia:dirty_index_read([user_permission_db, user_permission_fs], Hash, #user_permission.hash2) of
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

