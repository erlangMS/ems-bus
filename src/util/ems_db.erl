%%********************************************************************
%% @title Module ems_db
%% @version 1.0.0
%% @doc Module that provides interface with the database.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_db).

-export([start/2]).
-export([get/2, exist/2, all/1, 
		 insert/1, insert/2, update/1, delete/2, delete/1, 
		 match/2, 
		 find/1, find/2, find/3, find/4, find/5, 
		 find_by_id/2, find_by_id/3, filter/2,
		 find_first/2, find_first/3, find_first/4, filter_condition_parse_value_with_scape/2, 
		 sort/2, field_position/3]).
-export([init_sequence/2, sequence/1, sequence/2, current_sequence/1]).
-export([init_counter/2, counter/2, current_counter/1, inc_counter/1, dec_counter/1]).
-export([get_connection/1, release_connection/1, get_sqlite_connection_from_csv_file/1, create_datasource_from_map/3, create_datasource_from_map/4, 
		 command/2, select_count/2, is_database_in_restricted_mode/1]).
-export([get_param/1, get_param/2, set_param/2, get_re_param/2]).
-export([get_transient_param/1, get_transient_param/2, set_transient_param/2, get_re_transient_param/2]).

-export([filter_with_sort/2]).


-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").



%% *********** Database schema creation ************

start(PrivPath, DatabasePath) ->
	Nodes = [node()],

	% Define a pasta de armazenamento dos databases
	application:set_env(mnesia, dir, DatabasePath),

	ems_logger:format_info("ems_db initialize database storage \033[01;34m\"~s\"\033[0m.", [DatabasePath]),
	
	mnesia:create_schema(Nodes),
	mnesia:start(),

    mnesia:create_table(service_datasource, [{type, set},
											 {ram_copies, Nodes},
											 {attributes, record_info(fields, service_datasource)}]),

    mnesia:create_table(counter, [{type, set},
								  {ram_copies, Nodes},
								  {attributes, record_info(fields, sequence)}]),

    mnesia:create_table(stat_counter_hist, [{type, set},
								    {disc_copies, Nodes},
								    {attributes, record_info(fields, stat_counter_hist)},
								    {record_name, stat_counter_hist}]),

    mnesia:create_table(sequence, [{type, set},
								   {disc_copies, Nodes},
								   {attributes, record_info(fields, sequence)}]),

    mnesia:create_table(ctrl_sqlite_table, [{type, set},
											{disc_copies, Nodes},
											{attributes, record_info(fields, ctrl_sqlite_table)}]),

    mnesia:create_table(ctrl_params, [{type, set},
									  {disc_copies, Nodes},
									  {attributes, record_info(fields, ctrl_params)}]),

    mnesia:create_table(ctrl_transient_params, [{type, set},
											    {ram_copies, Nodes},
											    {attributes, record_info(fields, ctrl_params)},
											    {record_name, ctrl_params}]),

    mnesia:create_table(user_cache_lru, [{type, set},
										  {ram_copies, Nodes},
										  {index, [#user.login]},
										  {attributes, record_info(fields, user)},
										  {record_name, user}]),

    mnesia:create_table(user_fs, [{type, set},
								 {ram_copies, Nodes},
								  {index, [#user.codigo, #user.login, #user.name, #user.cpf, #user.email]},
								  {attributes, record_info(fields, user)},
								  {record_name, user}]),

    mnesia:create_table(user_db, [{type, set},
								  {disc_copies, Nodes},
								  {index, [#user.codigo, #user.login, #user.name, #user.cpf, #user.email]},
								  {attributes, record_info(fields, user)},
								  {record_name, user}]),

    mnesia:create_table(user2_db, [{type, set},
								  {disc_copies, Nodes},
								  {index, [#user.codigo, #user.login, #user.name, #user.cpf, #user.email]},
								  {attributes, record_info(fields, user)},
								  {record_name, user}]),

    mnesia:create_table(user3_db, [{type, set},
								  {disc_copies, Nodes},
								  {index, [#user.codigo, #user.login, #user.name, #user.cpf, #user.email]},
								  {attributes, record_info(fields, user)},
								  {record_name, user}]),

    mnesia:create_table(user_history, [{type, set},
									  {disc_copies, Nodes},
									  {index, [#user_history.user_id]},
									  {attributes, record_info(fields, user_history)},
									  {record_name, user_history}]),

    mnesia:create_table(user_aluno_ativo_db, [{type, set},
								  {disc_copies, Nodes},
								  {index, [#user.codigo, #user.login, #user.name, #user.cpf, #user.email]},
								  {attributes, record_info(fields, user)},
								  {record_name, user}]),

    mnesia:create_table(user_aluno_inativo_db, [{type, set},
								  {disc_copies, Nodes},
								  {index, [#user.codigo, #user.login, #user.name, #user.cpf, #user.email]},
								  {attributes, record_info(fields, user)},
								  {record_name, user}]),

    mnesia:create_table(user_dados_funcionais_fs, [{type, set},
								  {ram_copies, Nodes},
								  {attributes, record_info(fields, user_dados_funcionais)},
								  {record_name, user_dados_funcionais}]),

    mnesia:create_table(user_dados_funcionais_db, [{type, set},
								  {disc_copies, Nodes},
								  {attributes, record_info(fields, user_dados_funcionais)},
								  {record_name, user_dados_funcionais}]),

    mnesia:create_table(user_email_fs, [{type, set},
 								  {ram_copies, Nodes},
								  {attributes, record_info(fields, user_email)},
								  {record_name, user_email}]),

    mnesia:create_table(user_email_db, [{type, set},
								  {disc_copies, Nodes},
								  {attributes, record_info(fields, user_email)},
								  {record_name, user_email}]),

    mnesia:create_table(user_endereco_fs, [{type, set},
 								  {ram_copies, Nodes},
								  {attributes, record_info(fields, user_endereco)},
								  {record_name, user_endereco}]),

    mnesia:create_table(user_endereco_db, [{type, set},
								  {disc_copies, Nodes},
								  {attributes, record_info(fields, user_endereco)},
								  {record_name, user_endereco}]),

    mnesia:create_table(user_telefone_fs, [{type, set},
 								  {ram_copies, Nodes},
								  {attributes, record_info(fields, user_telefone)},
								  {record_name, user_telefone}]),

    mnesia:create_table(user_telefone_db, [{type, set},
								  {disc_copies, Nodes},
								  {attributes, record_info(fields, user_telefone)},
								  {record_name, user_telefone}]),

	mnesia:create_table(user_perfil_fs, [{type, set},
									    {ram_copies, Nodes},
										{index, [#user_perfil.user_id, #user_perfil.client_id]},
										{attributes, record_info(fields, user_perfil)},
										{record_name, user_perfil}]),

	mnesia:create_table(user_perfil_db, [{type, set},
										{disc_copies, Nodes},
										{index, [#user_perfil.user_id, #user_perfil.client_id]},
									    {attributes, record_info(fields, user_perfil)},
									    {record_name, user_perfil}]),

	mnesia:create_table(user_permission_fs, [{type, set},
										{ram_copies, Nodes},
										{index, [#user_permission.user_id, #user_permission.client_id]},
										{attributes, record_info(fields, user_permission)},
										{record_name, user_permission}]),

	mnesia:create_table(user_permission_db, [{type, set},
										{disc_copies, Nodes},
										{index, [#user_permission.user_id, #user_permission.client_id]},
									    {attributes, record_info(fields, user_permission)},
									    {record_name, user_permission}]),

    mnesia:create_table(client_db, [{type, set},
									{disc_copies, Nodes},
									{attributes, record_info(fields, client)},
									{record_name, client}]),

    mnesia:create_table(client_fs, [{type, set},
								    {ram_copies, Nodes},
									{attributes, record_info(fields, client)},
									{record_name, client}]),

    mnesia:create_table(catalog_schema, [{type, set},
										 {disc_copies, Nodes},
										 {attributes, record_info(fields, catalog_schema)}]),

    mnesia:create_table(service_owner, [{type, set},
	 							  {disc_copies, Nodes},
								  {attributes, record_info(fields, service_owner)}]),

    mnesia:create_table(catalog_get_fs, [{type, set},
									  {ram_copies, Nodes},
									  {index, [#service.rowid]},
									  {attributes, record_info(fields, service)},
									  {record_name, service}]),

    mnesia:create_table(catalog_post_fs, [{type, set},
 									  {ram_copies, Nodes},
									  {index, [#service.rowid]},
									  {attributes, record_info(fields, service)},
									  {record_name, service}]),

    mnesia:create_table(catalog_put_fs, [{type, set},
									  {ram_copies, Nodes},
									  {index, [#service.rowid]},
									  {attributes, record_info(fields, service)},
									  {record_name, service}]),

    mnesia:create_table(catalog_delete_fs, [{type, set},
									  {ram_copies, Nodes},
									  {index, [#service.rowid]},
									  {attributes, record_info(fields, service)},
									  {record_name, service}]),

    mnesia:create_table(catalog_options_fs, [{type, set},
									      {ram_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_kernel_fs, [{type, set},
										  {ram_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_re_fs, [{type, set},
									      {ram_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_get_db, [{type, set},
										  {disc_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_post_db, [{type, set},
										  {disc_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_put_db, [{type, set},
										  {disc_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_delete_db, [{type, set},
										  {disc_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(catalog_options_db, [{type, set},
											  {disc_copies, Nodes},
											  {index, [#service.rowid]},
											  {attributes, record_info(fields, service)},
											  {record_name, service}]),

    mnesia:create_table(catalog_kernel_db, [{type, set},
											  {disc_copies, Nodes},
											  {index, [#service.rowid]},
											  {attributes, record_info(fields, service)},
											  {record_name, service}]),

    mnesia:create_table(catalog_re_db, [{type, set},
										  {disc_copies, Nodes},
										  {index, [#service.rowid]},
										  {attributes, record_info(fields, service)},
										  {record_name, service}]),

    mnesia:create_table(auth_oauth2_access_token_table, [{type, set},
														{disc_copies, Nodes},
														{attributes, record_info(fields, auth_oauth2_access_token)},
														{record_name, auth_oauth2_access_token}]),

    mnesia:create_table(auth_oauth2_access_code_table, [{type, set},
														{disc_copies, Nodes},
														{attributes, record_info(fields, auth_oauth2_access_code)},
														{record_name, auth_oauth2_access_code}]),

    mnesia:create_table(auth_oauth2_refresh_token_table, [{type, set},
														{disc_copies, Nodes},
														{attributes, record_info(fields, auth_oauth2_refresh_token)},
														{record_name, auth_oauth2_refresh_token}]),

	mnesia:wait_for_tables([service_datasource,
							sequence,
							counter,
							ctrl_params,
							ctrl_transient_params,
							user_fs, 
							user_db,
							user2_db,
							user3_db,
							user_history,
							user_aluno_ativo_db,
							user_aluno_inativo_db,
							user_cache_lru,
							user_dados_funcionais_fs,
							user_dados_funcionais_db,
							user_email_fs,
							user_email_db,
							user_endereco_fs,
							user_endereco_db,
							user_telefone_fs,
							user_telefone_db,
							user_perfil_fs,
							user_perfil_db,
							user_permission_fs,
							user_permission_db,
							client_db,
							client_fs,
							ctrl_sqlite_table,
							catalog_schema,
							service_owner,
							catalog_get_fs,
							catalog_post_fs,
							catalog_put_fs,
							catalog_delete_fs,
							catalog_options_fs,
							catalog_kernel_fs,
							catalog_re_fs,
							catalog_get_db,
							catalog_post_db,
							catalog_put_db,
							catalog_delete_db,
							catalog_options_db,
							catalog_kernel_db,
							catalog_re_db,
							stat_counter_hist,
							auth_oauth2_access_token_table,
							auth_oauth2_access_code_table,
							auth_oauth2_refresh_token_table
							], 120000),
	ems_logger:format_info("ems_db database storage initialized."),
							
	set_param(priv_path, PrivPath),
	set_param(database_path, DatabasePath),
	ems_cache:new(ems_db_parsed_query_cache),
							
	ok.



%% *********** Functions for CRUD ************

insert(RecordType, Record) ->
	F = fun() ->
		case element(2, Record) of
			undefined ->
				Id = sequence(RecordType),
				Record1 = setelement(2, Record, Id),
				mnesia:write(Record1),
				Record1;
			Id -> 
				case mnesia:read(RecordType, Id) of
					[] -> mnesia:write(Record),
						  Record;
					_ -> {error, ealready_exist}
				end
		end
	end,		
	case mnesia:transaction(F) of
		{atomic, Result} -> {ok, Result};
		Error -> Error
	end.

insert(Record) ->
	RecordType = element(1, Record),
	insert(RecordType, Record).

update(Record) ->
	F = fun() -> mnesia:write(Record) end,
	mnesia:transaction(F),
	ok.

delete(RecordType, Id) when is_list(Id) ->
	Id2 = list_to_integer(Id),
	delete(RecordType, Id2);
	
delete(RecordType, Id) ->
	F = fun() -> mnesia:delete({RecordType, Id}) end,
	mnesia:transaction(F),
	ok.

delete(Record) ->
	F = fun() -> mnesia:delete(Record) end,
	mnesia:transaction(F),
	ok.
	

%% ************* Funções para gerar sequences *************

init_sequence(Name, Value) ->
     {atomic, ok} =	mnesia:transaction(fun() ->
						mnesia:write(#sequence{key=Name, index=Value})
					end),
     ok.
sequence(Name) ->  mnesia:dirty_update_counter(sequence, Name, 1).
current_sequence(Name) -> mnesia:dirty_update_counter(sequence, Name, 0).
sequence(Name, Inc) -> mnesia:dirty_update_counter(sequence, Name, Inc).


%% ************* Funções para gerar counters *************

init_counter(Name, Value) ->
     {atomic, ok} =	mnesia:transaction(fun() ->
						mnesia:write(#counter{key=Name, value=Value})
					end),
     ok.
inc_counter(Name) ->  mnesia:dirty_update_counter(counter, Name, 1).
dec_counter(Name) ->  mnesia:dirty_update_counter(counter, Name, -1).
current_counter(Name) -> mnesia:dirty_update_counter(counter, Name, 0).
counter(Name, Inc) -> mnesia:dirty_update_counter(counter, Name, Inc).
     

%% ************* Funções para armazenar parâmetros em crtl_params *************

-spec get_param(atom()) -> any().
get_param(ParamName) -> 
	case mnesia:dirty_read(ctrl_params, ParamName) of
		[] -> undefined;
		[#ctrl_params{value = Value}] -> Value
	end.

-spec get_param(atom(), function() | any()) -> any().
get_param(ParamName, Fun) when is_function(Fun) -> 
	case mnesia:dirty_read(ctrl_params, ParamName) of
		[] -> 
			Value = Fun(),
			set_param(ParamName, Value),
			Value;
		[#ctrl_params{value = Value}] -> Value
	end;
get_param(ParamName, DefaultValue) -> 
	case mnesia:dirty_read(ctrl_params, ParamName) of
		[] -> 
			set_param(ParamName, DefaultValue),
			DefaultValue;
		[#ctrl_params{value = Value}] -> Value
	end.
	
-spec get_re_param(atom(), string()) -> {re_pattern, term(), term(), term(), term()}.	
get_re_param(ParamName, DefaultREPattern) -> 
	case mnesia:dirty_read(ctrl_params, ParamName) of
		[] -> 
			{ok, Value} = re:compile(DefaultREPattern),
			set_param(ParamName, Value),
			Value;
		[#ctrl_params{value = Value}] -> Value
	end.

-spec set_param(atom(), any()) -> ok.
set_param(ParamName, ParamValue) -> 
	P = #ctrl_params{name = ParamName, value = ParamValue},
	mnesia:dirty_write(ctrl_params, P).


%% ************* Funções para armazenar parâmetros em crtl_transient_params *************

-spec get_transient_param(atom()) -> any().
get_transient_param(ParamName) -> 
	case mnesia:dirty_read(ctrl_transient_params, ParamName) of
		[] -> undefined;
		[#ctrl_params{value = Value}] -> Value
	end.

-spec get_transient_param(atom(), function() | any()) -> any().
get_transient_param(ParamName, Fun) when is_function(Fun) -> 
	case mnesia:dirty_read(ctrl_transient_params, ParamName) of
		[] -> 
			Value = Fun(),
			set_transient_param(ParamName, Value),
			Value;
		[#ctrl_params{value = Value}] -> Value
	end;
get_transient_param(ParamName, DefaultValue) -> 
	case mnesia:dirty_read(ctrl_transient_params, ParamName) of
		[] -> 
			set_transient_param(ParamName, DefaultValue),
			DefaultValue;
		[#ctrl_params{value = Value}] -> Value
	end.
	
-spec get_re_transient_param(atom(), string()) -> {re_pattern, term(), term(), term(), term()}.	
get_re_transient_param(ParamName, DefaultREPattern) -> 
	case mnesia:dirty_read(ctrl_transient_params, ParamName) of
		[] -> 
			{ok, Value} = re:compile(DefaultREPattern),
			set_transient_param(ParamName, Value),
			Value;
		[#ctrl_params{value = Value}] -> Value
	end.
	
-spec set_transient_param(atom(), any()) -> ok.
set_transient_param(ParamName, ParamValue) -> 
	P = #ctrl_params{name = ParamName, value = ParamValue},
	mnesia:dirty_write(ctrl_transient_params, P).


%% Funções para get and release connection

% Get the connection from a datasource (postgresql, sqlserver, sqlite, ou mnesia)
get_connection(Datasource = #service_datasource{type = postgresql}) ->
	get_odbc_connection(Datasource);
get_connection(Datasource = #service_datasource{type = sqlserver}) ->
	get_odbc_connection(Datasource);
get_connection(Datasource = #service_datasource{type = csvfile}) ->
	get_sqlite_connection_from_csv_file(Datasource);
get_connection(Datasource = #service_datasource{type = mnesia}) ->
	{ok, Datasource}.

% Release a conection from a datasource
release_connection(#service_datasource{type = mnesia}) -> ok;
release_connection(Datasource) -> ems_odbc_pool:release_connection(Datasource).

get_odbc_connection(Datasource) -> ems_odbc_pool:get_connection(Datasource).

create_sqlite_from_csv(#service_datasource{connection = Filename,
										   table_name = TableName,
										   csv_delimiter = Delimiter}) -> 
	FilenamePath = ?CSV_FILE_PATH ++ "/" ++ Filename,
	case filelib:last_modified(FilenamePath) of
		0 -> {error, ecsvfile_not_exist};
		LastModified ->
			SqliteFile = ?DATABASE_PATH ++ "/sqlite3_" ++ TableName,
			DatabaseExist = filelib:is_file(SqliteFile), 
			F = fun() ->
				Ctrl = ems_util:hd_or_empty(mnesia:read(ctrl_sqlite_table, Filename)),
				case Ctrl =:= [] orelse not DatabaseExist orelse Ctrl#ctrl_sqlite_table.last_modified =/= LastModified of
					true ->
						Csv2SqliteCmd = lists:flatten(io_lib:format('~s "~s" "~s" "~s" "~s"',
																	 [?CSV2SQLITE_PATH,
																	  SqliteFile, 
																	  TableName, 
																	  FilenamePath, 
																	  Delimiter])),
						ems_logger:info("ems_db execute \033[0;32mOS Command\033[0m: ~p.", [Csv2SqliteCmd]),
						os:cmd(Csv2SqliteCmd),
						mnesia:write(#ctrl_sqlite_table{file_name = Filename, last_modified = LastModified});
					false -> 
						% Não foi necessário criar o arquivo csv. Não houve mudança no arquivo csv
						ok
				end
			end,
			mnesia:activity(transaction, F),
			SqliteFile
	end.


get_sqlite_connection_from_csv_file(Datasource = #service_datasource{driver = Driver}) -> 
	SqliteFile = create_sqlite_from_csv(Datasource),
	case Driver of
		odbc ->
			StringConnection = lists:flatten(io_lib:format("DRIVER=SQLite;Version=3;Database=~s;", [SqliteFile])),
			ems_odbc_pool:get_connection(Datasource#service_datasource{type = sqlite, connection = StringConnection});
		sqlite3 ->
			ems_odbc_pool:get_connection(Datasource#service_datasource{type = sqlite, connection = SqliteFile});
		_ -> erlang:error(einvalid_driver_datasource)
	end.


%create_sqlite_virtual_table_from_csv_file(Filename, TableName, _PrimaryKey) -> 
%	{ok, Conn} = ems_db:get_odbc_connection("DRIVER=SQLite;Version=3;New=True;"),
%	odbc:sql_query(Conn, "select load_extension(\"/usr/lib/x86_64-linux-gnu/libsqlite3_mod_csvtable.so\")"),
%	CreateTableDDL = lists:flatten(io_lib:format("create virtual table ~s using csvtable(\"~s\")", [TableName, Filename])),
%	odbc:sql_query(Conn, CreateTableDDL),
%	odbc:commit(Conn, commit),
%	{ok, Conn}.


%% ************* Funções para pesquisa *************

%
% Find object by id. Return all fields.
% Ex.: ems_db:find_by_id(catalog_schema, 1).
% Sample result is {<<"id">>,1},{<<"name">>,<<"exemplo">>}
%
-spec get(atom() | list(atom()), non_neg_integer()) -> {ok, tuple()} | {error, enoent}.
get(Tab, Id) when is_atom(Tab) ->
	io:format("entrou no get da consulta >>>>>>>>>>>>> ~n~n"),
	case mnesia:dirty_read(Tab, Id) of
		[] -> 
			io:format("Erro na consulta ~p~p~n",[Tab,Id]),
			{error, enoent};
		[Record|_] -> {ok, Record}
	end;
get([], _) -> {error, enoent};
get([Tab|TabT], Id) ->
	case mnesia:dirty_read(Tab, Id) of
		[] -> get(TabT, Id);
		[Record|_] -> {ok, Record}
	end.


%
% Check exist record by id. Return boolean.
% Ex.: ems_db:exist(catalog_schema, 1).
% Sample result is {<<"id">>,1},{<<"name">>,<<"exemplo">>}
%
-spec exist(atom() | list(atom()), non_neg_integer()) -> boolean().
exist(Tab, Id) when is_atom(Tab) ->
	case mnesia:dirty_read(Tab, Id) of
		[] -> false;
		_ -> true
	end;
exist([], _) -> false;
exist([Tab|TabT], Id) ->
	case mnesia:dirty_read(Tab, Id) of
		[] -> exist(TabT, Id);
		_ -> true
	end.


-spec all(atom()) -> {ok, list(tuple())}.
all(Tab) ->
	F = fun() ->
		  qlc:e(
			 qlc:q([X || X <- mnesia:table(Tab)])
		  )
	   end,
	Records = mnesia:activity(async_dirty, F),
	{ok, Records}.


%
% Find object by id. Return all fields. 
% Ex.: ems_db:find_by_id(catalog_schema, 1).
% Sample result is {<<"id">>,1},{<<"name">>,<<"exemplo">>}
%
-spec find_by_id(atom() | list(atom()), non_neg_integer()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find_by_id(Tab, Id) -> get(Tab, Id).

%
% Find object by id
% Ex.: ems_db:find_by_id(catalog_schema, 1, [id, name]).
% Sample result is [[{<<"id">>,1},{<<"name">>,<<"exemplo">>}]]
%
-spec find_by_id(atom() | list(atom()), non_neg_integer(), list()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find_by_id(Tab, Id, FieldList) ->
	case get(Tab, Id) of
		{ok, Record} -> select_fields(Record, FieldList);
		Error -> Error
	end.


-spec find(atom()) -> {ok, tuple()} | {error, enoent}.
find(Tab) -> all(Tab).


%
% Find objects. Return all fields.
% Ex.: ems_db:find(catalog_schema, [{id, "==", 1}]).
% Sample result is [[{<<"id">>,1},{<<"name">>,<<"exemplo">>}]]
%
-spec find(atom(), list()) -> {ok, tuple()} | {error, enoent}.
find(Tab, FilterList) -> find(Tab, [], FilterList, []).


%
% Find objects
% Ex.: ems_db:find(catalog_schema, [id, name], [{id, "==", 1}]).
% Sample result is [[{<<"id">>,1},{<<"name">>,<<"exemplo">>}]]
%
-spec find(atom() | list(atom()), list(), list(), list()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find(Tab, FieldList, FilterList, SortList) when is_atom(Tab) ->
    Records = filter(Tab, FilterList),
	{ok, Records2} = select_fields(Records, FieldList),
	sort(Records2, SortList);
find(TabList, FieldList, FilterList, SortList) ->
    Records = filter_multi_tab(TabList, FilterList, []),
    {ok, Records2} = select_fields(Records, FieldList),
    sort(Records2, SortList).

-spec find(atom() | list(atom()), list(), list()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find(Tab, FieldList, FilterList) when is_atom(Tab) ->
    Records = filter(Tab, FilterList),
	select_fields(Records, FieldList);
find(TabList, FieldList, FilterList) ->
    Records = filter_multi_tab(TabList, FilterList, []),
    select_fields(Records, FieldList).


filter_multi_tab([], _, Result) -> Result;
filter_multi_tab([Tab|TabT], FilterList, Result) ->
    Records = filter(Tab, FilterList),
	case Records =/= [] of
		true -> filter_multi_tab(TabT, FilterList, Result ++ Records);
		false -> filter_multi_tab(TabT, FilterList, Result)
	end.


sort_fields_table([Map|_]) -> [ binary_to_atom(R, utf8) || R <- maps:keys(Map)].

sort(Records, SortList) -> 
	FieldsTable = sort_fields_table(Records),
	List = ems_util:list_map_to_list_tuple(Records),
	List2 = sort_(List, FieldsTable, SortList),
	ems_util:list_tuple_to_list_map(List2).

sort_(List, _, []) -> List;
sort_(List, FieldsTable, [SortField|SortFieldT]) ->
	FldPos = field_position(SortField, FieldsTable, 1),
	List2 = lists:sort(fun(A, B) -> 
			{_, FldValue1} = lists:nth(FldPos, A),
			{_, FldValue2} = lists:nth(FldPos, B),
			FldValue1 < FldValue2 
		end, List),
	sort_(List2, FieldsTable, SortFieldT).


%
% Find objects with limits
% Ex.: ems_db:find(catalog_schema, [id, name], [{id, "==", 1}], 1, 1).
% Sample result is [[{<<"id">>,1},{<<"name">>,<<"exemplo">>}]]
%
-spec find(atom() | list(atom()), list(), list(), non_neg_integer(), non_neg_integer()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find(Tab, FieldList, FilterList, Limit, Offset) when is_atom(Tab) -> 
    Records = filter_with_limit(Tab, FilterList, Limit, Offset),
	select_fields(Records, FieldList);
find(Tab, FieldList, FilterList, Limit, Offset) -> 
	find_(Tab, FieldList, FilterList, Limit, Offset, []).


find_([], FieldList, _, Limit, Offset, Result) -> 
	{ok, Result2} = select_fields(Result, FieldList),
	case Offset > length(Result2) of
		true -> {ok, []};
		false -> {ok, lists:sublist(Result2, Offset, Limit)}
	end;
find_([Tab|TabT], FieldList, FilterList, Limit, Offset, Result) -> 
    Records = filter_with_limit(Tab, FilterList, Limit, Offset),
    case Records =/= [] of 
		true -> find_(TabT, FieldList, FilterList, Limit, Offset, Result ++ Records);
		false -> find_(TabT, FieldList, FilterList, Limit, Offset, Result)
	end.

	


%
% Find first objects
% Ex.: ems_db:find_first(catalog_schema, [{id, "==", 1}]).
% Sample result is [{<<"id">>,1},{<<"name">>,<<"exemplo">>}]
%
-spec find_first(atom(), list()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find_first(Tab, FilterList) -> find_first(Tab, [], FilterList).


%
% Find first objects
% Ex.: ems_db:find_first(catalog_schema, [id, name], [{id, "==", 1}]).
% Sample result is [{<<"id">>,1},{<<"name">>,<<"exemplo">>}]
%
-spec find_first(atom() | list(atom()), list(), list()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find_first(Tab, FieldList, FilterList) when is_atom(Tab) ->
    case filter_with_limit(Tab, FilterList, 1, 1) of
		[] -> {error, enoent};
		[FirstRecord|_] -> select_fields(FirstRecord, FieldList)
	end;
find_first([], _, _) -> {error, enoent};
find_first([Tab|TabT], FieldList, FilterList) ->
    case filter_with_limit(Tab, FilterList, 1, 1) of
		[] -> find_first(TabT, FieldList, FilterList);
		[FirstRecord|_] -> select_fields(FirstRecord, FieldList)
	end.


%
% Find first objects
% Ex.: ems_db:find_first(catalog_schema, [id, name], [{id, "==", 1}], 1).
% Sample result is [{<<"id">>,1},{<<"name">>,<<"exemplo">>}]
%
-spec find_first(atom() | list(atom()), list(), list(), non_neg_integer()) -> {ok, tuple()} | {ok, map()} | {error, enoent}.
find_first(Tab, FieldList, FilterList, Offset) when is_atom(Tab) ->
    case filter_with_limit(Tab, FilterList, 1, Offset) of
		[] -> {error, enoent};
		[FirstRecord|_] -> select_fields(FirstRecord, FieldList)
	end;
find_first([], _, _, _) -> {error, enoent};
find_first([Tab|TabT], FieldList, FilterList, Offset) ->
    case filter_with_limit(Tab, FilterList, 1, Offset) of
		[] -> find_first(TabT, FieldList, FilterList, Offset);
		[FirstRecord|_] -> select_fields(FirstRecord, FieldList)
	end.
	


%	
% Filter objects
% Ex.: ems_db:filter(catalog_schema, [{id, "==", 1}]). 
% Sample result is 
%[{catalog_schema,1,<<"exemplo">>,<<"schema de exemplo">>,
%                 #{<<"properties">> => #{<<"age">> => #{<<"description">> => <<"Age in years">>,
%                       <<"minimum">> => 0,
%                       <<"type">> => <<"integer">>},
%                     <<"firstName">> => #{<<"type">> => <<"string">>},
%                     <<"lastName">> => #{<<"type">> => <<"string">>}},
%                   <<"required">> => [<<"firstName">>,<<"lastName">>],
%                   <<"title">> => <<"Example Schema">>,
%                   <<"type">> => <<"object">>}}]
%
-spec filter(atom(), list(tuple())) -> list(tuple()).
filter(Tab, []) -> 
	F = fun() ->
		  qlc:e(
			 qlc:q([R || R <- mnesia:table(Tab)])
		  )
	   end,
	mnesia:activity(async_dirty, F);
filter(Tab, FilterList = [{F1, "==", V1}]) ->
	Fields =  mnesia:table_info(Tab, attributes),
	FieldPosition = field_position(F1, Fields, 1),
	FieldType = ems_schema:get_data_type_field(Tab, FieldPosition),
	case filter_condition_parse_value(V1, FieldType) of
		{ok, FieldValue} -> 
			case field_has_index(FieldPosition, Tab) of
				false ->
					FieldPositionTable = FieldPosition + 1, 
					Fun = fun() -> 
								qlc:e(qlc:q([R || R <- mnesia:table(Tab), element(FieldPositionTable, R) == FieldValue])) 
						  end,
					mnesia:activity(async_dirty, Fun);
				true ->
					case FieldPosition of
						1 -> mnesia:dirty_read(Tab, FieldValue);
						_ -> 
							FieldPositionTable = FieldPosition + 1, 
							mnesia:dirty_index_read(Tab, FieldValue, FieldPositionTable)  
					end
			end;	
		{error, Reason} -> 
			ems_logger:warn("ems_db filter invalid query on table ~p with filter ~p. Reason: ~p.", [Tab, FilterList, Reason]),
			[]
	end;
filter(Tab, FilterList = [{F1, "==", V1}, {F2, "==", V2}]) ->
	Fields =  mnesia:table_info(Tab, attributes),
	FieldPositionF1 = field_position(F1, Fields, 1),
	FieldTypeF1 = ems_schema:get_data_type_field(Tab, FieldPositionF1),
	case filter_condition_parse_value(V1, FieldTypeF1) of
		{ok, FieldValueF1} -> 
			FieldPositionF2 = field_position(F2, Fields, 1),
			FieldTypeF2 = ems_schema:get_data_type_field(Tab, FieldPositionF2),
			case filter_condition_parse_value(V2, FieldTypeF2) of
				{ok, FieldValueF2} -> 
					FieldPositionTableF1 = FieldPositionF1 + 1, 
					FieldPositionTableF2 = FieldPositionF2 + 1, 
					Fun = fun() -> 
								qlc:e(qlc:q([R || R <- mnesia:table(Tab), element(FieldPositionTableF1, R) == FieldValueF1, element(FieldPositionTableF2, R) == FieldValueF2])) 
						  end,
					mnesia:activity(async_dirty, Fun);
				{error, Reason} -> 
					ems_logger:warn("ems_db filter invalid query on table ~p with filter ~p. Reason: ~p.", [Tab, FilterList, Reason]),
					[]
			end;
		{error, Reason} -> 
			ems_logger:warn("ems_db filter invalid query on table ~p with filter ~p. Reason: ~p.", [Tab, FilterList, Reason]),
			[]
	end;
filter(Tab, FilterList) when is_list(FilterList) -> 
	try
		F = fun() ->
				ExprWhere = filter_condition(Tab, FilterList),
				ExprQuery = binary_to_list(iolist_to_binary([<<"[R || R <- mnesia:table(">>, atom_to_binary(Tab, utf8), <<"), ">>, ExprWhere, <<"].">>])),
				?DEBUG("ems_db filter generate expression query ~p to access table ~p.", [ExprQuery, Tab]),
				qlc:string_to_handle(ExprQuery)
			end,
		ParsedQuery = ems_cache:get(ems_db_parsed_query_cache, ?DB_PARSED_QUERY_CACHE_TIMEOUT, {filter, Tab, FilterList}, F),
		mnesia:activity(async_dirty, fun () -> qlc:eval(ParsedQuery) end)
	catch
		_Exception:Reason -> 
			ems_logger:warn("ems_db filter invalid query on table ~p with filter ~p. Reason: ~p.", [Tab, FilterList, Reason]),
			[]
	end;
filter(Tab, FilterTuple) when is_tuple(FilterTuple) ->
	filter(Tab, [FilterTuple]).


filter_condition(Tab, FilterList) -> 
	FieldsTable =  mnesia:table_info(Tab, attributes),
	iolist_to_binary(filter_condition(Tab, FilterList, FieldsTable, [])).
	
filter_condition(_, [], _, Result) -> 
	lists:reverse(Result);
filter_condition(Tab, [{'or', FilterList}|[]], FieldsTable, Result) ->
	ResultOr = filter_condition_or(Tab, FilterList, FieldsTable, Result),
	filter_condition(Tab, [], FieldsTable, [ResultOr | Result]);
filter_condition(Tab, [{'or', FilterList}|T], FieldsTable, Result) ->
	ResultOr = filter_condition_or(Tab, FilterList, FieldsTable, Result),
	filter_condition(Tab, T, FieldsTable, [ResultOr ++ <<", ">> | Result]);

filter_condition(Tab, [{'and', FilterList}|[]], FieldsTable, Result) ->
	ResultAnd = filter_condition(Tab, FilterList, FieldsTable, Result),
	filter_condition(Tab, [], FieldsTable, [ResultAnd | Result]);
filter_condition(Tab, [{'and', FilterList}|T], FieldsTable, Result) ->
	ResultAnd = filter_condition(Tab, FilterList, FieldsTable, Result),
	filter_condition(Tab, T, FieldsTable, [ResultAnd ++ <<", ">> | Result]);

filter_condition(Tab, [{F, Op, V}|[]], FieldsTable, Result) ->
	Condition = filter_condition_create(Tab, F, Op, V, FieldsTable, <<>>),
	filter_condition(Tab, [], FieldsTable, [Condition | Result]);
filter_condition(Tab, [{F, Op, V}|T], FieldsTable, Result) ->
	Condition = filter_condition_create(Tab, F, Op, V, FieldsTable, <<", ">>),
	filter_condition(Tab, T, FieldsTable, [Condition | Result]).

filter_condition_or(_, [], _, Result) -> 
	lists:reverse(Result);
filter_condition_or(Tab, [{'or', FilterList}|[]], FieldsTable, Result) ->
	ResultOr = filter_condition_or(Tab, FilterList, FieldsTable, Result),
	filter_condition(Tab, [], FieldsTable, [[<<" orelse ">> | ResultOr] | Result]);
filter_condition_or(Tab, [{'or', FilterList}|T], FieldsTable, Result) ->
	ResultOr = filter_condition_or(Tab, FilterList, FieldsTable, Result),
	filter_condition(Tab, T, FieldsTable, [[<<" orelse ">> | ResultOr] | Result]);

filter_condition_or(Tab, [{F, Op, V}|[]], FieldsTable, Result) ->
	Condition = filter_condition_create(Tab, F, Op, V, FieldsTable, <<>>),
	filter_condition_or(Tab, [], FieldsTable, [Condition | Result]);
filter_condition_or(Tab, [{F, Op, V}|T], FieldsTable, Result) ->
	Condition = filter_condition_create(Tab, F, Op, V, FieldsTable, <<" orelse ">>),
	filter_condition_or(Tab, T, FieldsTable, [Condition | Result]).

filter_condition_create(Tab, F, Op, V, FieldsTable, BoolOp) ->
	FieldAtom = filter_condition_parse_field(F),
	FieldPosition = field_position(FieldAtom, FieldsTable, 1),
	FieldType = ems_schema:get_data_type_field(Tab, FieldPosition),
	case filter_condition_parse_value_with_scape(V, FieldType) of
		{ok, FieldValue} -> 
			FieldPositionTable = integer_to_binary(FieldPosition + 1),
			[ <<"element(">>, FieldPositionTable, <<", R) ">>, Op, <<" ">>, FieldValue, BoolOp ];
		{error, Reason} -> erlang:error(Reason)
	end.
	

-spec filter_condition_parse_field(any()) -> atom().	
filter_condition_parse_field(F) when is_list(F) -> list_to_atom(string:to_lower(F));
filter_condition_parse_field(F) when is_binary(F) -> list_to_atom(string:to_lower(binary_to_list(F)));
filter_condition_parse_field(F) when is_atom(F) -> F;
filter_condition_parse_field(_) -> erlang:error(einvalid_field_filter).


-spec filter_condition_parse_value(any(), atom()) -> {ok, any()} | {error, einvalid_fieldtype}.
filter_condition_parse_value(Value, binary_type) ->
	try
		case is_binary(Value) of
			true -> {ok, Value};
			false ->
				case is_list(Value) of
					true -> {ok, list_to_binary(Value)};
					false -> 
						case is_integer(Value) of
							true -> {ok, integer_to_binary(Value)};
							false -> {error, einvalid_fieldtype}
						end
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value(Value, string_type) ->
	try
		case is_list(Value) of
			true -> {ok, binary_to_list(Value)};
			false ->
				case is_binary(Value) of
					true -> {ok, binary_to_list(Value)};
					false -> 
						case is_integer(Value) of
							true -> {ok, integer_to_list(Value)};
							false -> {error, einvalid_fieldtype}
						end
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value(Value, non_neg_integer_type) ->
	try
		case is_integer(Value) of
			true -> {ok, Value};
			false ->
				case is_binary(Value) of
					true -> {ok, binary_to_integer(Value)};
					false -> 
						case is_list(Value) of
							true -> {ok, list_to_integer(Value)};
							false -> {error, einvalid_fieldtype}
						end
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value(Value, boolean_type) ->
	case ems_util:parse_bool(Value) of
		true -> {ok, true};
		false -> {ok, false}
	end;
filter_condition_parse_value(Value, atom_type) ->
	try
		case is_binary(Value) of
			true -> {ok, binary_to_atom(Value, utf8)};
			false -> 
				case is_list(Value) of
					true -> {ok, list_to_atom(Value)};
					false -> {error, einvalid_fieldtype}
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value(Value, undefined) when is_binary(Value) -> {ok, Value};
filter_condition_parse_value(Value, undefined) when is_list(Value) -> {ok, list_to_binary(Value)};
filter_condition_parse_value(Value, undefined) when is_integer(Value) -> {ok, integer_to_binary(Value)};
filter_condition_parse_value(Value, undefined) when is_atom(Value) -> {ok, atom_to_binary(Value, utf8)};
filter_condition_parse_value(_, undefined) -> {error, einvalid_fieldtype}.


-spec filter_condition_parse_value_with_scape(any(), atom()) -> {ok, any()} | {error, einvalid_fieldtype}.
filter_condition_parse_value_with_scape(Value, binary_type) ->
	try
		case is_binary(Value) of
			true -> {ok, iolist_to_binary([ <<"<<\"">>, Value, <<"\">>">>])};
			false ->
				case is_list(Value) of
					true -> {ok, iolist_to_binary([ <<"<<\"">>, list_to_binary(Value), <<"\">>">>])};
					false -> 
						case is_integer(Value) of
							true -> {ok, iolist_to_binary([ <<"<<\"">>, integer_to_binary(Value), <<"\">>">>])};
							false -> {error, einvalid_fieldtype}
						end
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value_with_scape(Value, string_type) ->
	try
		case is_list(Value) of
			true -> {ok, binary_to_list(iolist_to_binary([ <<"\"">>, Value, <<"\"">>]))};
			false ->
				case is_binary(Value) of
					true -> {ok, binary_to_list(iolist_to_binary([ <<"\"">>, Value, <<"\"">>]))};
					false -> 
						case is_integer(Value) of
							true -> {ok, binary_to_list(iolist_to_binary([ <<"\"">>, integer_to_binary(Value), <<"\"">>]))};
							false -> {error, einvalid_fieldtype}
						end
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value_with_scape(Value, non_neg_integer_type) ->
	try
		case is_integer(Value) of
			true -> {ok, integer_to_list(Value)};
			false ->
				case is_binary(Value) of
					true -> {ok, integer_to_list(binary_to_integer(Value))};
					false -> 
						case is_list(Value) of
							true -> {ok, integer_to_list(list_to_integer(Value))};
							false -> {error, einvalid_fieldtype}
						end
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value_with_scape(Value, boolean_type) ->
	case ems_util:parse_bool(Value) of
		true -> {ok, <<"true">>};
		false -> {ok, <<"false">>}
	end;
filter_condition_parse_value_with_scape(Value, atom_type) ->
	try
		case is_binary(Value) of
			true -> {ok, binary_to_list(Value)};
			false -> 
				case is_list(Value) of
					true -> {ok, Value};
					false -> {error, einvalid_fieldtype}
				end
		end
	catch 
		_Exception:_Reason -> {error, einvalid_fieldtype}
	end;
filter_condition_parse_value_with_scape(Value, undefined) when is_binary(Value) -> {ok, iolist_to_binary([ <<"<<\"">>, Value, <<"\">>">>])};
filter_condition_parse_value_with_scape(Value, undefined) when is_list(Value) -> {ok, iolist_to_binary([ <<"\"">>, list_to_binary(Value), <<"\"">>])};
filter_condition_parse_value_with_scape(Value, undefined) when is_integer(Value) -> {ok, integer_to_binary(Value)};
filter_condition_parse_value_with_scape(Value, undefined) when is_atom(Value) -> {ok, atom_to_binary(Value, utf8)};
filter_condition_parse_value_with_scape(_, undefined) -> {error, einvalid_fieldtype}.


filter_with_sort(Tab, []) -> 
	F = fun() ->
		  qlc:e(
			qlc:sort(
					qlc:q([R || R <- mnesia:table(Tab)]), [{order, descending}]
				)
		  )
	   end,
	mnesia:activity(async_dirty, F).


%	
% Filter objects with limit
% Ex.: ems_db:filter_with_limit(catalog_schema, [{id, "==", 1}], 1, 1). 
% Sample result is 
%[{catalog_schema,1,<<"exemplo">>,<<"schema de exemplo">>,
%                 #{<<"properties">> => #{<<"age">> => #{<<"description">> => <<"Age in years">>,
%                       <<"minimum">> => 0,
%                       <<"type">> => <<"integer">>},
%                     <<"firstName">> => #{<<"type">> => <<"string">>},
%                     <<"lastName">> => #{<<"type">> => <<"string">>}},
%                   <<"required">> => [<<"firstName">>,<<"lastName">>],
%                   <<"title">> => <<"Example Schema">>,
%                   <<"type">> => <<"object">>}}]
%
-spec filter_with_limit(atom(), list(), non_neg_integer(), non_neg_integer()) -> list(tuple()).
filter_with_limit(Tab, [], Limit, Offset) -> 
	TabSize = mnesia:table_info(Tab, size),
	case TabSize == 0 orelse Offset > TabSize orelse Limit < 1 orelse Offset < 1 of
		true -> [];
		false ->
			F = fun() ->
				  case Offset > 1 of
						true ->
							Q = qlc:cursor(qlc:q([R || R <- mnesia:table(Tab)])),
							qlc:next_answers(Q, Offset-1), % discart records
							Records = qlc:next_answers(Q, Limit),
							qlc:delete_cursor(Q),
							Records;
						false ->
							Q = qlc:cursor(qlc:q([R || R <- mnesia:table(Tab)])),
							Records = qlc:next_answers(Q, Limit),
							qlc:delete_cursor(Q),
							Records
				  end
			   end,
			mnesia:activity(async_dirty, F)
	end;
filter_with_limit(Tab, Filter = [{_, "==", _}], Limit, Offset) ->
	TabSize = mnesia:table_info(Tab, size),
	case TabSize == 0 orelse Offset > TabSize orelse Limit < 1 orelse Offset < 1 of
		true -> [];
		false ->
			Records = filter(Tab, Filter),
			case Offset > length(Records) of
				true -> [];
				false -> lists:sublist(Records, Offset, Limit)
			end
	end;
filter_with_limit(Tab, FilterList, Limit, Offset) when is_list(FilterList) -> 
	TabSize = mnesia:table_info(Tab, size),
	case TabSize == 0 orelse Offset > TabSize orelse Limit < 1 orelse Offset < 1 of
		true -> [];
		false ->
			Records = filter(Tab, FilterList),
			case Offset > length(Records) of
				true -> [];
				false -> lists:sublist(Records, Offset, Limit)
			end
	end;
filter_with_limit(Tab, FilterTuple, Limit, Offset) when is_tuple(FilterTuple) -> 	
	filter_with_limit(Tab, [FilterTuple], Limit, Offset).



% match objects and faster than filter
% Ex.: ems_db:match(catalog_schema, [{id, 1}]).
% Sample result is like filter function
match(Tab, FilterList) -> 
	FieldsTable =  mnesia:table_info(Tab, attributes),
	Record = ems_schema:new_(Tab),
	Match = match(Tab, FilterList, FieldsTable, Record),
	mnesia:activity(async_dirty, fun() -> mnesia:match_object(Match) end).
		
match(_, [], _, Record) -> Record;
match(Tab, [{F, _, V}|T], FieldsTable, Record) -> 
	Fld = field_position(F, FieldsTable, 1),
	Record2 = setelement(Fld, Record, field_value(V)),
    match(Tab, T, FieldsTable, Record2);
match(Tab, [{F, V}|T], FieldsTable, Record) -> 
	Fld = field_position(F, FieldsTable, 1),
	Record2 = setelement(Fld, Record, field_value(V)),
    match(Tab, T, FieldsTable, Record2).


% select fields of object or list objects
% Ex.: ems_db:select_fields(#user{id = 1, name = "agilar", email = "evertonagilar@gmail.com"}, [name]).
% Sample result is [#{<<"name">> => "agilar"}]
-spec select_fields(list(tuple()) | tuple(), list()) -> {ok, list(map())}.
select_fields(ListRecord, []) -> {ok, ListRecord};
select_fields(Tuple, FieldList) when is_tuple(Tuple) -> 
    FieldList2 = ems_util:list_to_binlist(FieldList),
	List = ems_schema:to_list([Tuple], FieldList2),
	{ok, [Map]} = select_fields_agregate(List, []),
	{ok, Map};
select_fields(ListRecord, FieldList) -> 
    FieldList2 = ems_util:list_to_binlist(FieldList),
	List = ems_schema:to_list(ListRecord, FieldList2),
	select_fields_agregate(List, []).
	
select_fields_agregate([], Result) -> {ok, lists:reverse(Result)};
select_fields_agregate([H|T], Result) -> 
	select_fields_agregate(T, [maps:from_list(H)|Result]).
	

%	
% Return true/false if field has index on mnesia table
% Ex.: field_has_index(4, user). 
% return true
-spec field_has_index(non_neg_integer(), atom()) -> boolean().
field_has_index(1, _) -> true;
field_has_index(FldPos, Tab) ->
	Indexes =  mnesia:table_info(Tab, index),
	lists:member(FldPos, Indexes).


% Return the field position on record
-spec field_position(binary() | string() | atom(), list(atom()), non_neg_integer()) -> non_neg_integer().
field_position(Field, Fields, Idx) when is_list(Field) -> 
	field_position_search(list_to_atom(Field), Fields, Idx);
field_position(Field, Fields, Idx) when is_binary(Field) -> 
	field_position_search(binary_to_atom(Field, utf8), Fields, Idx);
field_position(Field, Fields, Idx) -> 
	field_position_search(Field, Fields, Idx).

field_position_search(_, [], _) -> erlang:error(einvalid_field_filter);
field_position_search(Field, [F|Fs], Idx) ->
	case Field == F of
		true -> Idx;
		_ -> field_position_search(Field, Fs, Idx+1)
	end.


% Return the field as binary
field_value(V) when is_list(V) -> list_to_binary(V);
field_value(V) -> V.


-spec parse_datasource_type(binary()) -> atom().
parse_datasource_type(<<"mnesia">>) -> mnesia;
parse_datasource_type(<<"sqlserver">>) -> sqlserver;
parse_datasource_type(<<"postgresql">>) -> postgresql;
parse_datasource_type(<<"csvfile">>) -> csvfile;
parse_datasource_type(<<"db2">>) -> db2;
parse_datasource_type(_) -> erlang:error(einvalid_datasource_type_property).

-spec parse_data_source_driver(atom(), binary()) -> atom().
parse_data_source_driver(csvfile, <<"sqlite3">>) -> sqlite3;
parse_data_source_driver(csvfile, <<"odbc">>) -> odbc;
parse_data_source_driver(csvfile, _) -> erlang:error(einvalid_datasource_driver_property);
parse_data_source_driver(_, _) -> undefined.

-spec parse_datasource_csvdelimiter(atom(), binary()) -> string().
parse_datasource_csvdelimiter(csvfile, <<";">>) -> ";";
parse_datasource_csvdelimiter(csvfile, <<"|">>) -> "|";
parse_datasource_csvdelimiter(csvfile, <<",">>) -> ",";
parse_datasource_csvdelimiter(csvfile, <<"@">>) -> "@";
parse_datasource_csvdelimiter(csvfile, undefined) ->  ";";
parse_datasource_csvdelimiter(csvfile, <<>>) ->  ";";
parse_datasource_csvdelimiter(csvfile, _) -> erlang:error(einvalid_datasource_csvdelimiter_property);
parse_datasource_csvdelimiter(_, _) -> undefined.

-spec parse_datasource_table_name(atom(), binary() | list()) -> string() | list(atom()) | atom().
parse_datasource_table_name(_, undefined) -> undefined;
parse_datasource_table_name(_, <<>>) -> undefined;
parse_datasource_table_name(mnesia, Value) -> ems_util:binlist_to_atomlist(Value);
parse_datasource_table_name(_, Value) -> binary_to_list(Value).

-spec parse_datasource_fields(atom(), binary() | list()) -> string() | list(atom()) | atom().
parse_datasource_fields(_, undefined) -> [];
parse_datasource_fields(_, <<>>) -> [];
parse_datasource_fields(mnesia, Value) -> ems_util:binlist_to_atomlist(Value);
parse_datasource_fields(_, Value) -> binary_to_list(Value).


-spec parse_remap_fields_reverso(map()) -> map().
parse_remap_fields_reverso(undefined) -> undefined;
parse_remap_fields_reverso(RemapFields) ->
	RemapFieldsList = maps:to_list(RemapFields),
	RemapFieldsRev = [{Value, Key} || {Key,Value} <- RemapFieldsList],
	maps:from_list(RemapFieldsRev).


-spec parse_datasource_remap_fields(list(map())) -> map().
parse_datasource_remap_fields(undefined) -> undefined;
parse_datasource_remap_fields([]) -> undefined;
parse_datasource_remap_fields([MapH|MapT] = ListMap) when is_list(ListMap) -> 
	parse_datasource_remap_fields(MapT, MapH);
parse_datasource_remap_fields(_) -> 
	erlang:error(einvalid_datasource_remap_fields_property).

parse_datasource_remap_fields([], Result) -> Result;
parse_datasource_remap_fields([MapH|MapT], Result) -> 
	parse_datasource_remap_fields(MapT, maps:merge(MapH, Result)).


-spec parse_datasource_primary_key(atom(), binary()) -> string() | atom().
parse_datasource_primary_key(_, undefined) -> undefined;
parse_datasource_primary_key(_, <<>>) -> undefined;
parse_datasource_primary_key(mnesia, Value) -> binary_to_atom(Value, utf8);
parse_datasource_primary_key(_, Value) -> binary_to_list(Value).

-spec parse_datasource_foreign_key(atom(), binary()) -> string() | atom().
parse_datasource_foreign_key(_, undefined) -> undefined;
parse_datasource_foreign_key(_, <<>>) -> undefined;
parse_datasource_foreign_key(mnesia, Value) -> binary_to_atom(Value, utf8);
parse_datasource_foreign_key(_, Value) -> binary_to_list(Value).

-spec parse_datasource_foreign_table_name(atom(), binary() | list()) -> string() | list(atom()) | atom().
parse_datasource_foreign_table_name(_, undefined) -> undefined;
parse_datasource_foreign_table_name(mnesia, Value) -> ems_util:binlist_to_atomlist(Value);
parse_datasource_foreign_table_name(_, Value) -> ems_util:binlist_to_list(Value).

-spec parse_datasource_sql(atom(), binary()) -> string().
parse_datasource_sql(_, undefined) -> undefined;
parse_datasource_sql(_, <<>>) -> undefined;
parse_datasource_sql(mnesia, _) -> erlang:error(einvalid_datasource_sql_property);
parse_datasource_sql(_, Value) -> binary_to_list(Value).

-spec parse_datasource_connection(atom(), binary()) -> string().
parse_datasource_connection(mnesia, undefined) -> undefined;
parse_datasource_connection(mnesia, <<>>) -> undefined;
parse_datasource_connection(mnesia, _) -> erlang:error(einvalid_datasource_connection_property);
parse_datasource_connection(_, undefined) -> erlang:error(einvalid_datasource_connection_property);
parse_datasource_connection(_, <<>>) -> erlang:error(einvalid_datasource_connection_property);
parse_datasource_connection(_, Value) -> binary_to_list(Value).

-spec parse_datasource_sql_check_validation_connection(atom(), binary()) -> string().
parse_datasource_sql_check_validation_connection(sqlserver, undefined) -> "select 1";
parse_datasource_sql_check_validation_connection(sqlserver, Value) -> binary_to_list(Value);
parse_datasource_sql_check_validation_connection(postgresql, undefined) -> "select 1";
parse_datasource_sql_check_validation_connection(postgresql, Value) -> binary_to_list(Value);
parse_datasource_sql_check_validation_connection(_, undefined) -> undefined;
parse_datasource_sql_check_validation_connection(_, <<>>) -> undefined;
parse_datasource_sql_check_validation_connection(_, _) -> erlang:error(einvalid_datasource_sql_check_validation_connection_property).

parse_extends_datasource(Map, GlobalDatasources) ->
	case maps:get(<<"extends">>, Map, undefined) of
		undefined -> Map;
		NameBaseDs ->
			case maps:get(NameBaseDs, GlobalDatasources, undefined) of
				undefined -> erlang:error(eextends_inexistent_datasource);
				BaseDs -> 
					BaseDsMap = #{<<"type">> => atom_to_binary(BaseDs#service_datasource.type, utf8),
								  <<"connection">> => list_to_binary(BaseDs#service_datasource.connection),
								  <<"timeout">> => BaseDs#service_datasource.timeout,
								  <<"driver">> => atom_to_binary(BaseDs#service_datasource.driver, utf8),
								  <<"sql_check_valid_connection">> => list_to_binary(BaseDs#service_datasource.sql_check_valid_connection),
								  <<"check_valid_connection_timeout">> => BaseDs#service_datasource.check_valid_connection_timeout,
								  <<"close_idle_connection_timeout">> => BaseDs#service_datasource.close_idle_connection_timeout,
								  <<"max_pool_size">> => BaseDs#service_datasource.max_pool_size,
								  <<"show_remap_fields">> => BaseDs#service_datasource.show_remap_fields},
					maps:merge(BaseDsMap, Map)
			end
	end.
	
-spec create_datasource_from_map(map(), non_neg_integer(), #config{}) -> #service_datasource{} | undefined.
create_datasource_from_map(Map, Rowid, Config) ->
	create_datasource_from_map(Map, Rowid, Config, undefined).

-spec create_datasource_from_map(map(), non_neg_integer(), #config{}, binary()) -> #service_datasource{} | undefined.
create_datasource_from_map(Map, Rowid, #config{ems_datasources = GlobalDatasources, 
											   custom_variables = Variables, 
											   log_show_odbc_pool_activity = LogShowOdbcPoolActivityConfig}, DsName) ->
	try
		put(parse_step, parse_extends_datasource),
		M = parse_extends_datasource(Map, GlobalDatasources),
		
		put(parse_step, type),
		Type = parse_datasource_type(maps:get(<<"type">>, M, undefined)),

		put(parse_step, driver),
		Driver = parse_data_source_driver(Type, maps:get(<<"driver">>, M, undefined)),

		put(parse_step, connection),
		Connection0 = parse_datasource_connection(Type, maps:get(<<"connection">>, M, undefined)),
		Connection = ems_util:replace_all_vars(Connection0, Variables),
		
		put(parse_step, table_name),
		TableName = parse_datasource_table_name(Type, maps:get(<<"table_name">>, M, undefined)),
		
		put(parse_step, fields),
		Fields = parse_datasource_fields(Type, maps:get(<<"fields">>, M, undefined)),
		
		put(parse_step, parse_datasource_remap_fields),
		RemapFields = parse_datasource_remap_fields(maps:get(<<"remap_fields">>, M, undefined)),
		
		put(parse_step, parse_remap_fields_reverso),
		RemapFieldsRev = parse_remap_fields_reverso(RemapFields),
		
		put(parse_step, primary_key),
		PrimaryKey = parse_datasource_primary_key(Type, maps:get(<<"primary_key">>, M, undefined)),
		
		put(parse_step, foreign_key),
		ForeignKey = parse_datasource_foreign_key(Type, maps:get(<<"foreign_key">>, M, undefined)),
		
		put(parse_step, foreign_table_name),
		ForeignTableName = parse_datasource_foreign_table_name(Type, maps:get(<<"foreign_table_name">>, M, undefined)),
		
		put(parse_step, csv_delimiter),
		CsvDelimiter = parse_datasource_csvdelimiter(Type, maps:get(<<"csv_delimiter">>, M, undefined)),
		
		put(parse_step, show_remap_fields),
		ShowRemapFields = ems_util:parse_bool(maps:get(<<"show_remap_fields">>, M, true)),
		
		put(parse_step, sql),
		Sql = parse_datasource_sql(Type, maps:get(<<"sql">>, M, undefined)),
		
		put(parse_step, timeout),
		Timeout0 = ems_util:parse_range(maps:get(<<"timeout">>, M, ?MAX_TIME_ODBC_QUERY), 1, ?MAX_TIME_ODBC_QUERY),
		case Timeout0 < 960000 of
			true -> Timeout = 960000;
			false -> Timeout = Timeout0
		end,
		
		put(parse_step, max_pool_size),
		MaxPoolSize = ems_util:parse_range(maps:get(<<"max_pool_size">>, M, 1), 1, ?MAX_CONNECTION_BY_POOL),
		
		put(parse_step, sql_check_valid_connection),
		SqlCheckValidConnection = parse_datasource_sql_check_validation_connection(Type, maps:get(<<"sql_check_valid_connection">>, M, undefined)),
		
		put(parse_step, close_idle_connection_timeout),
		CloseIdleConnectionTimeout = ems_util:parse_range(maps:get(<<"close_idle_connection_timeout">>, M, ?CLOSE_IDLE_CONNECTION_TIMEOUT), 1, ?MAX_CLOSE_IDLE_CONNECTION_TIMEOUT),
		
		put(parse_step, check_valid_connection_timeout),
		CheckValidConnectionTimeout = ems_util:parse_range(maps:get(<<"check_valid_connection_timeout">>, M, ?CHECK_VALID_CONNECTION_TIMEOUT), 1, ?MAX_CLOSE_IDLE_CONNECTION_TIMEOUT),

		put(parse_step, log_show_odbc_pool_activity),
		LogShowOdbcPoolActivity = ems_util:parse_bool(maps:get(<<"log_show_odbc_pool_activity">>, M, LogShowOdbcPoolActivityConfig)),

		put(parse_step, ctrlhash),
		CtrlHash = erlang:phash2([Rowid, Type, Driver, Connection, TableName, Fields, 
								  PrimaryKey, ForeignKey, ForeignTableName, CsvDelimiter, 
								  Sql, Timeout, MaxPoolSize, 
								  SqlCheckValidConnection, CloseIdleConnectionTimeout, 
								  CheckValidConnectionTimeout, RemapFields, ShowRemapFields]),

		case ems_db:find_first(service_datasource, [{ctrl_hash, "==", CtrlHash}]) of
			  {error, enoent} ->										
					Id = ems_db:inc_counter(service_datasource),
					IdStr = integer_to_list(Id),
					ConnectionCountMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_conn_count"])),
					ConnectionCreatedMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_created_count"])),
					ConnectionClosedMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_closed_count"])),
					ConnectionShutdownMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_shutdown_count"])),
					ConnectionReuseMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_reuse_count"])),
					ConnectionUnavailableMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_unavailable_count"])),
					ConnectionMaxPoolSizeExceededMetricName = list_to_atom(lists:concat(["ems_odbc_pool_", IdStr, "_max_pool_size_exceeded_count"])),
					
					put(parse_step, new_service_datasource),
					NewDs = #service_datasource{id = Id,
												ds_name = DsName,
												rowid = Rowid,
												type = Type,
												driver = Driver,
												connection = Connection,
												table_name = TableName,
												fields = Fields,
												primary_key = PrimaryKey,
												foreign_key = ForeignKey,
												foreign_table_name = ForeignTableName,
												csv_delimiter = CsvDelimiter,
												sql = Sql,
												timeout = Timeout,
												max_pool_size = MaxPoolSize,
												remap_fields = RemapFields,
												remap_fields_rev = RemapFieldsRev,
												show_remap_fields = ShowRemapFields,
												log_show_odbc_pool_activity = LogShowOdbcPoolActivity,
												connection_count_metric_name = ConnectionCountMetricName,
												connection_created_metric_name = ConnectionCreatedMetricName,
												connection_closed_metric_name = ConnectionClosedMetricName,
												connection_shutdown_metric_name = ConnectionShutdownMetricName,
												connection_reuse_metric_name = ConnectionReuseMetricName,
												connection_unavailable_metric_name = ConnectionUnavailableMetricName,
												connection_max_pool_size_exceeded_metric_name = ConnectionMaxPoolSizeExceededMetricName,
												sql_check_valid_connection = SqlCheckValidConnection,
												check_valid_connection_timeout = CheckValidConnectionTimeout,
												close_idle_connection_timeout = CloseIdleConnectionTimeout,
												ctrl_hash = CtrlHash
											},
					ems_db:insert(NewDs),
					NewDs;
			  {ok, ExistDs} -> ExistDs
		 end										
	catch
		_:Reason-> 
			ems_logger:format_error("ems_db parse invalid datasource ~p on ~p. Reason: ~p.\n", [Map, get(parse_step), Reason]),
			undefined
	end.
	

command(Datasource, Sql) when is_integer(Datasource) ->
	case ems_db:get(service_datasource, Datasource) of
		{ok, Record} -> command(Record, Sql);
		{error, enoent} -> ems_logger:format_error("ems_db test_datasource datasource not found.\n")	
	end;
command(Datasource, Sql) when is_tuple(Datasource) ->
	try
		case ems_odbc_pool:get_connection(Datasource) of
			{ok, Datasource2} -> 
				ems_logger:format_info("ems_db command connection passed."),
				case ems_odbc_pool:param_query(Datasource2, Sql, []) of
					{_, _, Records} -> 
						ems_odbc_pool:release_connection(Datasource2),
						ems_logger:format_info("ems_db command data:\n"),
						io:format("~p\n", [Records]);
					Error1 -> 
						ems_odbc_pool:release_connection(Datasource2),
						ems_logger:format_error("ems_db command exception. Reason: ~p.\n", [Error1])
				end;
			Error2 -> 
				ems_logger:format_error("ems_db command exception. Reason: ~p.\n", [Error2])
		end
	catch
		_:Reason-> ems_logger:format_error("ems_db command exception. Reason: ~p.\n", [Reason])
	end.
		

select_count(Datasource, Sql) when is_integer(Datasource) ->
	case ems_db:get(service_datasource, Datasource) of
		{ok, Record} -> select_count(Record, Sql);
		{error, enoent} -> ems_logger:format_error("ems_db select_count datasource not found.\n")	
	end;
select_count(Datasource, Sql) when is_tuple(Datasource) ->
	try
		case ems_odbc_pool:get_connection(Datasource) of
			{ok, Datasource2} -> 
				ems_logger:format_info("ems_db select_count connection passed."),
				case ems_odbc_pool:select_count(Datasource2, Sql) of
					{ok, NumRows} -> 
						ems_odbc_pool:release_connection(Datasource2),
						ems_logger:format_info("ems_db select_count: ~p rows\n", [NumRows]);
					Error1 -> 
						ems_odbc_pool:release_connection(Datasource2),
						ems_logger:format_error("ems_db select_count exception. Reason: ~p.", [Error1])
				end;
			Error2 -> 
				ems_logger:format_error("ems_db select_count exception. Reason: ~p.\n", [Error2])
		end
	catch
		_:Reason-> ems_logger:format_error("ems_db select_count exception. Reason: ~p.\n", [Reason])
	end.


is_database_in_restricted_mode(Reason) when is_list(Reason) ->
	string:str(Reason, "security context") > 0;
is_database_in_restricted_mode(_) -> 
	false.
