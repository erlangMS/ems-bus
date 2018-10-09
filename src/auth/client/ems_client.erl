%%********************************************************************
%% @title Module ems_client
%% @version 1.0.0
%% @doc client class
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_client).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([insert/1, update/1, all/0, delete/1, 
		 find_by_id/1,		 
		 find_by_name/1,
		 find_by_id_and_secret/2,
		 to_json/1,
		 new_from_map/2,
		 get_table/1,
		 find/2,
		 all/1]).


-spec find_by_id(non_neg_integer()) -> {ok, #client{}} | {error, enoent}.
find_by_id(Id) -> 
	case ems_db:get([client_db, client_fs], Id) of
		{ok, Record} -> {ok, Record};
		_ -> {error, enoent}
	end.


-spec all() -> {ok, list()}.
all() -> 
	{ok, ListaUserDb} = ems_db:all(client_db),
	{ok, ListaUserFs} = ems_db:all(client_fs),
	{ok, ListaUserDb ++ ListaUserFs}.


	
-spec find_by_id_and_secret(non_neg_integer(), binary()) -> {ok, #client{}} | {error, enoent, einvalid_secret | undefined}.
find_by_id_and_secret(Id, Secret) ->
	case find_by_id(Id) of
		{ok, Client = #client{secret = CliSecret}} -> 
			case CliSecret =:= Secret orelse CliSecret =:= ems_util:criptografia_sha1(Secret)  of
				true -> {ok, Client};
				false -> {error, enoent, einvalid_client_secret}
			end;
		_ -> {error, enoent, undefined}
	end.



-spec find_by_name(binary() | string()) -> {ok, #client{}} | {error, enoent}.
find_by_name(<<>>) -> {error, enoent};
find_by_name("") -> {error, enoent};
find_by_name(undefined) -> {error, enoent};
find_by_name(Name) when is_list(Name) -> 
	find_by_name(list_to_binary(Name));
find_by_name(Name) -> 
	case ems_db:find_first(client_db, [{name, "==", Name}]) of
		{error, enoent} ->
			case ems_db:find_first(client_fs, [{name, "==", Name}]) of
				{error, enoent} -> {error, enoent};
				{ok, Record2} -> {ok, Record2}
			end;
		{ok, Record} -> {ok, Record}
	end.


-spec to_json(binary() | undefined) -> binary().
to_json(undefined) -> <<"{}"/utf8>>;
to_json(Client) ->
	iolist_to_binary([
		<<"{"/utf8>>,
			<<"\"id\":"/utf8>>, integer_to_binary(Client#client.id), <<","/utf8>>,
			<<"\"name\":\""/utf8>>, Client#client.name, <<"\""/utf8>>,
		<<"}"/utf8>>
		]).

	
-spec new_from_map(map(), #config{}) -> {ok, #client{}} | {error, atom()}.
new_from_map(Map, _Conf) ->
	try
		{ok, #client{
				id = maps:get(<<"id">>, Map),
				name = ?UTF8_STRING(maps:get(<<"name">>, Map)),
				secret = ?UTF8_STRING(maps:get(<<"secret">>, Map, <<"CPD">>)),
				redirect_uri = ems_util:to_lower_and_remove_backslash(?UTF8_STRING(maps:get(<<"redirect_uri">>, Map, <<>>))),
				description = ?UTF8_STRING(maps:get(<<"description">>, Map, <<>>)),
				scope =  ems_util:parse_oauth2_scope(maps:get(<<"scope">>, Map, <<>>)),
				version = ?UTF8_STRING(maps:get(<<"version">>, Map, <<"1.0.0">>)),
				active = ems_util:parse_bool(maps:get(<<"active">>, Map, true)),
				group = ?UTF8_STRING(maps:get(<<"group">>, Map, <<>>)),
				glyphicon = ?UTF8_STRING(maps:get(<<"glyphicon">>, Map, <<>>)),
				ctrl_path = maps:get(<<"ctrl_path">>, Map, <<>>),
				ctrl_file = maps:get(<<"ctrl_file">>, Map, <<>>),
				ctrl_modified = maps:get(<<"ctrl_modified">>, Map, undefined),
				ctrl_hash = erlang:phash2(Map)
			}
		}
	catch
		_Exception:Reason -> 
			ems_logger:format_warn("ems_client parse invalid client specification: ~p\n\t~p.\n", [Reason, Map]),
			{error, Reason}
	end.


-spec get_table(fs | db) -> client_db | client_fs.
get_table(db) -> client_db;
get_table(fs) -> client_fs.

-spec find(client_fs | client_db, non_neg_integer()) -> {ok, #client{}} | {error, enoent}.
find(Table, Id) ->
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(client_fs | client_db) -> list() | {error, atom()}.
all(Table) -> ems_db:all(Table).


%% middleware functions

insert(Client) -> 
	case valida(Client, insert) of
		ok -> ems_db:insert(Client);
		Error -> 
			Error
	end.

update(Client) -> 
	case valida(Client, update) of
		ok -> ems_db:update(Client);
		Error -> Error
	end.

delete(Id) -> ems_db:delete(client, Id).

valida(_Client, _Operation) -> ok.

