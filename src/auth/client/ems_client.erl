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
	ems_data_loader_ctl:register_activity(?MODULE),
	case mnesia:dirty_read(client_db, Id) of
		[] -> 
			case mnesia:dirty_read(client_fs, Id) of
				[] -> {error, enoent};
				[Record|_] -> {ok, Record}
			end;
		[Record|_] -> {ok, Record}
	end.


-spec all() -> {ok, list()}.
all() -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	{ok, ListaUserDb} = ems_db:all(client_db),
	{ok, ListaUserFs} = ems_db:all(client_fs),
	{ok, ListaUserDb ++ ListaUserFs}.


	
-spec find_by_id_and_secret(non_neg_integer(), binary()) -> {ok, #client{}} | {error, enoent, einvalid_secret | undefined}.
find_by_id_and_secret(Id, Secret) ->
	case find_by_id(Id) of
		{ok, Client = #client{secret = CliSecret, name = ClientName}} -> 
			case CliSecret =:= Secret orelse CliSecret =:= ems_util:criptografia_sha1(Secret)  of
				true -> {ok, Client};
				false -> 
					ems_logger:error("ems_client find_by_id_and_secret failed due invalid_secret \"~s\" for client ~p ~s. Expected secret: \"~s\".", [binary_to_list(Secret), Id, binary_to_list(ClientName), binary_to_list(CliSecret)]),
					{error, enoent, einvalid_client_secret}
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
	ems_data_loader_ctl:register_activity(?MODULE),
	case mnesia:dirty_index_read(client_db, Name, #client.name) of
		[] ->
			case mnesia:dirty_index_read(client_fs, Name, #client.name) of
				[] -> {error, enoent};
				[Record2|_] -> {ok, Record2}
			end;
		[Record|_] -> {ok, Record}
	end.


-spec to_json(binary() | undefined) -> binary().
to_json(undefined) -> <<"{}"/utf8>>;
to_json(Client = #client{json_cache = JsonCache}) ->
	ems_data_loader_ctl:register_activity(?MODULE),
	case JsonCache of
		undefined ->
			% Cache miss - compute JSON
			iolist_to_binary([
				<<"{"/utf8>>,
					<<"\"id\":"/utf8>>, integer_to_binary(Client#client.id), <<","/utf8>>,
					<<"\"name\":\""/utf8>>, Client#client.name, <<"\","/utf8>>,
					<<"\"description\":\""/utf8>>, Client#client.description, <<"\","/utf8>>,
					<<"\"active\":"/utf8>>, ems_util:boolean_to_binary(Client#client.active), 
				<<"}"/utf8>>
			]);
		CachedJson ->
			% Cache hit - return cached JSON
			CachedJson
	end.

	
-spec new_from_map(map(), #config{}) -> {ok, #client{}} | {error, atom()}.
new_from_map(Map, Conf) ->
	ems_data_loader_ctl:register_activity(?MODULE),
	try
		{ok, #client{
				id = maps:get(<<"id">>, Map),
				name = ?UTF8_STRING(maps:get(<<"name">>, Map)),
				secret = ?UTF8_STRING(maps:get(<<"secret">>, Map, <<"CPD">>)),
				redirect_uri = ems_util:normalize_url(?UTF8_STRING(maps:get(<<"redirect_uri">>, Map, <<>>))),
				description = ?UTF8_STRING(maps:get(<<"description">>, Map, <<>>)),
				scope =  ems_util:parse_oauth2_scope(maps:get(<<"scope">>, Map, <<>>)),
				state =  ?UTF8_STRING(maps:get(<<"state">>, Map, <<>>)),
				version = ?UTF8_STRING(maps:get(<<"version">>, Map, <<"1.0.0">>)),
				active = ems_util:parse_bool(maps:get(<<"active">>, Map, true)),
				group = ?UTF8_STRING(maps:get(<<"group">>, Map, <<>>)),
				glyphicon = ?UTF8_STRING(maps:get(<<"glyphicon">>, Map, <<>>)),
				rest_base_url = ?UTF8_STRING(maps:get(<<"rest_base_url">>, Map, Conf#config.rest_base_url)),
				rest_auth_url = ?UTF8_STRING(maps:get(<<"rest_auth_url">>, Map, Conf#config.rest_auth_url)),
				authorization_owner = maps:get(<<"authorization_owner">>, Map, []),
				user_agent = maps:get(<<"user_agent">>, Map, []),
				peer = maps:get(<<"peer">>, Map, []),
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
get_table(db) -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	client_db;
get_table(fs) -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	client_fs.

-spec find(client_fs | client_db, non_neg_integer()) -> {ok, #client{}} | {error, enoent}.
find(Table, Id) ->
	ems_data_loader_ctl:register_activity(?MODULE),
	case mnesia:dirty_read(Table, Id) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(client_fs | client_db) -> list() | {error, atom()}.
all(Table) -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	ems_db:all(Table).


%% middleware functions

insert(Client) -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	case valida(Client, insert) of
		ok -> ems_db:insert(Client);
		Error -> 
			Error
	end.

update(Client) -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	case valida(Client, update) of
		ok -> ems_db:update(Client);
		Error -> Error
	end.

delete(Id) -> 
	ems_data_loader_ctl:register_activity(?MODULE),
	ems_db:delete(client, Id).

valida(_Client, _Operation) -> ok.

