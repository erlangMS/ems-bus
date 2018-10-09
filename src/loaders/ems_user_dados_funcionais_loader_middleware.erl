%%********************************************************************
%% @title Module ems_user_dados_funcionais_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load dados funcionais
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_dados_funcionais_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, check_remove_records/2, after_load_or_update_checkpoint/1]).


-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	mnesia:table_info(user_dados_funcionais_db, size) == 0;
is_empty(fs) ->	mnesia:table_info(user_dados_funcionais_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) -> mnesia:table_info(user_dados_funcionais_db, size);
size_table(fs) -> mnesia:table_info(user_dados_funcionais_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(user_dados_funcionais_db) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(user_dados_funcionais_fs) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) -> 
	ems_db:init_sequence(user_dados_funcionais_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(user_dados_funcionais_fs, 0),
	ok.

-spec check_remove_records(list(), fs | db) -> non_neg_integer().	
check_remove_records(_Codigos, _SourceType) -> 0.
	

%% internal functions

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.user_dados_funcionais_path_search.
	

update_dados_funcionais_tabela_users(DadosFuncionais, UserTable, IdUser) -> 
	case ems_user:find(UserTable, IdUser) of
		{ok, User} ->
			User2 = User#user{type = DadosFuncionais#user_dados_funcionais.type,
							  subtype = DadosFuncionais#user_dados_funcionais.subtype},
			mnesia:dirty_write(UserTable, User2),
			ems_db:delete(user_cache_lru, IdUser);
		_ -> ok
	end.
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_user_dados_funcionais:new_from_map(Map, Conf) of
			{ok, NewRecord = #user_dados_funcionais{id = Id, ctrl_hash = CtrlHash}} -> 
				Table = ems_user_dados_funcionais:get_table(SourceType),
				case ems_user_dados_funcionais:find(Table, Id) of
					{error, enoent} -> 
						Record = NewRecord#user_dados_funcionais{ctrl_insert = CtrlDate},
						update_dados_funcionais_tabela_users(Record, case SourceType of
																		db -> user_db;
																		fs -> user_fs
																	 end, Id),
						{ok, Record, Table, insert};
					{ok, CurrentRecord = #user_dados_funcionais{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								?DEBUG("ems_user_dados_funcionais_loader_middleware update ~p from ~p.", [Map, SourceType]),
								Record = CurrentRecord#user_dados_funcionais{
												 type = NewRecord#user_dados_funcionais.type,
												 subtype = NewRecord#user_dados_funcionais.subtype,
												 active = NewRecord#user_dados_funcionais.active,
												 user_id = NewRecord#user_dados_funcionais.user_id,
												 ctrl_path = NewRecord#user_dados_funcionais.ctrl_path,
												 ctrl_file = NewRecord#user_dados_funcionais.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewRecord#user_dados_funcionais.ctrl_modified,
												 ctrl_hash = NewRecord#user_dados_funcionais.ctrl_hash
											},
								update_dados_funcionais_tabela_users(Record, case SourceType of
																				db -> user_db;
																				fs -> user_fs
																			 end, Id),
								{ok, Record, Table, update};
							false -> {ok, skip}
						end
				end;
			Error -> Error
		end

	catch
		_Exception:Reason -> {error, Reason}
	end.

-spec after_load_or_update_checkpoint(fs | db) -> ok.
after_load_or_update_checkpoint(_SourceType) ->	ok.
