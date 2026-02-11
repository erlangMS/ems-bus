%%********************************************************************
%% @title Module ems_user_email_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load email
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_user_email_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, get_table/1, after_load_or_update_checkpoint/1]).


-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	mnesia:table_info(user_email_db, size) == 0;
is_empty(fs) ->	mnesia:table_info(user_email_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) -> mnesia:table_info(user_email_db, size);
size_table(fs) -> mnesia:table_info(user_email_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(user_email_db) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(user_email_fs) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) -> 
	ems_db:init_sequence(user_email_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(user_email_fs, 0),
	ok.


-spec get_table(fs | db) -> user_email_db | user_email_fs.
get_table(db) -> user_email_db;
get_table(fs) -> user_email_fs.
	

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.user_email_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_user_email:new_from_map(Map, Conf) of
			{ok, NewRecord = #user_email{id = Id, ctrl_hash = CtrlHash, codigo = CodigoPessoa}} -> 
				Table = ems_user_email:get_table(SourceType),
				case ems_user_email:find(Table, Id) of
					{error, enoent} -> 
						Record = NewRecord#user_email{ctrl_insert = CtrlDate},
						{ok, Record, Table, insert};
					{ok, CurrentRecord = #user_email{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								%%?DEBUG("ems_user_email_loader_middleware update ~p from ~p.", [Map, SourceType]),
								Record = CurrentRecord#user_email{
												 codigo = CodigoPessoa,
												 email = NewRecord#user_email.email,
												 type = NewRecord#user_email.type,
												 ctrl_path = NewRecord#user_email.ctrl_path,
												 ctrl_file = NewRecord#user_email.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewRecord#user_email.ctrl_modified,
												 ctrl_hash = NewRecord#user_email.ctrl_hash
											},
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
	


