%%********************************************************************
%% @title Module ems_client_loader_middleware
%% @version 1.0.0
%% @doc Module responsible for load clients
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_client_loader_middleware).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([insert_or_update/5, is_empty/1, size_table/1, clear_table/1, reset_sequence/1, get_filename/0, check_remove_records/2, after_load_or_update_checkpoint/1]).

-spec is_empty(fs | db) -> boolean().
is_empty(db) ->	mnesia:table_info(client_db, size) == 0;
is_empty(fs) ->	mnesia:table_info(client_fs, size) == 0.
	

-spec size_table(fs | db) -> non_neg_integer().
size_table(db) -> mnesia:table_info(client_db, size);
size_table(fs) -> mnesia:table_info(client_fs, size).
	

-spec clear_table(fs | db) -> ok | {error, efail_clear_ets_table}.
clear_table(db) ->	
	case mnesia:clear_table(client_db) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end;
clear_table(fs) ->	
	case mnesia:clear_table(client_fs) of
		{atomic, ok} -> ok;
		_ -> {error, efail_clear_ets_table}
	end.
	
	
-spec reset_sequence(fs | db) -> ok.
reset_sequence(db) -> 
	ems_db:init_sequence(client_db, 0),
	ok;
reset_sequence(fs) ->	
	ems_db:init_sequence(client_fs, 0),
	ok.
	

-spec check_remove_records(list(), fs | db) -> non_neg_integer().	
check_remove_records(_Codigos, _SourceType) -> 0.


%% internal functions

-spec get_filename() -> list(tuple()).
get_filename() -> 
	Conf = ems_config:getConfig(),
	Conf#config.client_path_search.
	
	
-spec insert_or_update(map() | tuple(), tuple(), #config{}, atom(), insert | update) -> {ok, #service{}, atom(), insert | update} | {ok, skip} | {error, atom()}.
insert_or_update(Map, CtrlDate, Conf, SourceType, _Operation) ->
	try
		case ems_client:new_from_map(Map, Conf) of
			{ok, NewClient = #client{id = Id, ctrl_hash = CtrlHash}} -> 
				Table = ems_client:get_table(SourceType),
				case ems_client:find(Table, Id) of
					{error, enoent} -> 
						Client = NewClient#client{ctrl_insert = CtrlDate},
						{ok, Client, Table, insert};
					{ok, CurrentClient = #client{ctrl_hash = CurrentCtrlHash}} ->
						case CtrlHash =/= CurrentCtrlHash of
							true ->
								?DEBUG("ems_client_loader_middleware update ~p from ~p.", [Map, SourceType]),
								Client = CurrentClient#client{
												 name = NewClient#client.name,
												 secret = NewClient#client.secret,
												 redirect_uri = NewClient#client.redirect_uri,
												 description = NewClient#client.description,
												 scope = NewClient#client.scope,
												 active = NewClient#client.active,
												 version = NewClient#client.version,
												 group = NewClient#client.group,
												 glyphicon = NewClient#client.glyphicon,
												 rest_base_url = case NewClient#client.rest_base_url of
																	undefined -> Conf#config.rest_base_url;
																	null -> Conf#config.rest_base_url;
																	RestBaseUrlValue -> RestBaseUrlValue
																 end,
												 rest_auth_url = case NewClient#client.rest_auth_url of
																	undefined -> Conf#config.rest_auth_url;
																	null -> Conf#config.rest_auth_url;
																	RestAuthUrlValue -> RestAuthUrlValue
																 end,
												 authorization_owner = NewClient#client.authorization_owner,
												 user_agent = NewClient#client.user_agent,
												 peer = NewClient#client.peer,
												 forwarded_for = NewClient#client.forwarded_for,
												 ctrl_path = NewClient#client.ctrl_path,
												 ctrl_file = NewClient#client.ctrl_file,
												 ctrl_update = CtrlDate,
												 ctrl_modified = NewClient#client.ctrl_modified,
												 ctrl_hash = NewClient#client.ctrl_hash
											},
								{ok, Client, Table, update};
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
