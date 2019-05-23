%%********************************************************************
%% @title Module ems_user_perfil_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load user_perfil
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_perfil_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").


-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, get_table/1, after_load_or_update_checkpoint/1]).


-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	mnesia:table_info(user_perfil_db, size) == 0;
is_empty(fs) ->	mnesia:table_info(user_perfil_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) -> mnesia:table_info(user_perfil_db, size);
size_table(fs) -> mnesia:table_info(user_perfil_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(user_perfil_db) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(user_perfil_fs) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
-spec get_table(fs | db) -> user_perfil_db | user_perfil_fs.
get_table(db) -> user_perfil_db;
get_table(fs) -> user_perfil_fs.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) -> 
	ems_db:init_sequence(user_perfil_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(user_perfil_fs, 0),
	ok.
	

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.user_perfil_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_user_perfil:new_from_map(Map, Conf) of
			{ok, NewRecord = #user_perfil{id = Id, ctrl_hash = CtrlHash}} -> 
				Table = ems_user_perfil:get_table(SourceType),
				case ems_user_perfil:find(Table, Id) of
					{error, enoent} -> 
						UserPerfil = NewRecord#user_perfil{ctrl_insert = CtrlDate},
						{ok, UserPerfil, Table, insert};
					{ok, CurrentRecord = #user_perfil{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								?DEBUG("ems_user_perfil_perfil_loader_middleware update ~p from ~p.", [Map, SourceType]),
								UserPerfil = CurrentRecord#user_perfil{
												 perfil_id = NewRecord#user_perfil.perfil_id,
												 user_id = NewRecord#user_perfil.user_id,
												 client_id = NewRecord#user_perfil.client_id,
												 name = NewRecord#user_perfil.name,
												 ctrl_path = NewRecord#user_perfil.ctrl_path,
												 ctrl_file = NewRecord#user_perfil.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewRecord#user_perfil.ctrl_modified,
												 ctrl_hash = NewRecord#user_perfil.ctrl_hash
											},
								{ok, UserPerfil, Table, update};
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
