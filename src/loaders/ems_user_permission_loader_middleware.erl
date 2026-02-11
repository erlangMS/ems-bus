%%********************************************************************
%% @title Module ems_user_permission_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load user_permission
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_permission_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, get_table/1, after_load_or_update_checkpoint/1]).


-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	mnesia:table_info(user_permission_db, size) == 0;
is_empty(fs) ->	mnesia:table_info(user_permission_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) -> mnesia:table_info(user_permission_db, size);
size_table(fs) -> mnesia:table_info(user_permission_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(user_permission_db) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(user_permission_fs) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec get_table(fs | db) -> user_permission_db | user_permission_fs.
get_table(db) -> user_permission_db;
get_table(fs) -> user_permission_fs.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) -> 
	ems_db:init_sequence(user_permission_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(user_permission_fs, 0),
	ok.


-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.user_permission_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_user_permission:new_from_map(Map, Conf) of
			{ok, NewRecord = #user_permission{id = Id, ctrl_hash = CtrlHash}} -> 
				Table = ems_user_permission:get_table(SourceType),
				case ems_user_permission:find(Table, Id) of
					{error, enoent} -> 
						User = NewRecord#user_permission{ctrl_insert = CtrlDate},
						{ok, User, Table, insert};
					{ok, CurrentRecord = #user_permission{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								%%?DEBUG("ems_user_permission_perfil_loader_middleware update ~p from ~p.", [Map, SourceType]),
								UserPermission = CurrentRecord#user_permission{
												 user_id = NewRecord#user_permission.user_id,
												 client_id = NewRecord#user_permission.client_id,
												 perfil_id = NewRecord#user_permission.perfil_id,
												 name = NewRecord#user_permission.name,
												 url = NewRecord#user_permission.url,
												 grant_get = NewRecord#user_permission.grant_get,
												 grant_post = NewRecord#user_permission.grant_post,
												 grant_put = NewRecord#user_permission.grant_put,
												 grant_delete = NewRecord#user_permission.grant_delete,
												 position = NewRecord#user_permission.position,
												 ctrl_path = NewRecord#user_permission.ctrl_path,
												 ctrl_file = NewRecord#user_permission.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewRecord#user_permission.ctrl_modified,
												 ctrl_hash = NewRecord#user_permission.ctrl_hash,
												 glyphicon = NewRecord#user_permission.glyphicon
											},
								{ok, UserPermission, Table, update};
							false -> 
								{ok, skip}
						end
				end;
			Error -> Error
		end

	catch
		_Exception:Reason -> {error, Reason}
	end.

-spec after_load_or_update_checkpoint(fs | db) -> ok.
after_load_or_update_checkpoint(_SourceType) ->	ok.
