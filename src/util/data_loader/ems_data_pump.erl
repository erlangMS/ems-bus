%%********************************************************************
%% @title Module ems_data_pump
%% @version 1.0.0
%% @doc Module responsible for load records into mnesia tables
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_data_pump).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([data_pump/13]).

-spec data_pump(list(tuple()), tuple(), #config{}, binary(), binary(), 
									insert | update, non_neg_integer(), non_neg_integer(), 
									non_neg_integer(), non_neg_integer(), non_neg_integer(),
									fs | db, list()) -> ok.
data_pump([], _, _, _, _, _, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount, _, _) -> {ok, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount};
data_pump([H|T], CtrlDate, Conf, Name, Middleware, insert, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount, SourceType, Fields) ->
	case do_insert_record(H, CtrlDate, Conf, Name, Middleware, SourceType, Fields) of
		{ok, insert} -> data_pump(T, CtrlDate, Conf, Name, Middleware, insert, InsertCount+1, UpdateCount, ErrorCount, DisabledCount, SkipCount, SourceType, Fields);
		{ok, skip} -> data_pump(T, CtrlDate, Conf, Name, Middleware, insert, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount+1, SourceType, Fields);
		{error, edisabled} -> data_pump(T, CtrlDate, Conf, Name, Middleware, insert, InsertCount, UpdateCount, ErrorCount, DisabledCount+1, SkipCount, SourceType, Fields);
		_Error -> data_pump(T, CtrlDate, Conf, Name, Middleware, insert, InsertCount, UpdateCount, ErrorCount+1, DisabledCount, SkipCount, SourceType, Fields)
	end;
data_pump([H|T], CtrlDate, Conf, Name, Middleware, update, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount, SourceType, Fields) ->
	case do_update_record(H, CtrlDate, Conf, Name, Middleware, SourceType, Fields) of
		{ok, insert} -> 
			data_pump(T, CtrlDate, Conf, Name, Middleware, update, InsertCount+1, UpdateCount, ErrorCount, DisabledCount, SkipCount, SourceType, Fields);
		{ok, update} -> data_pump(T, CtrlDate, Conf, Name, Middleware, update, InsertCount, UpdateCount+1, ErrorCount, DisabledCount, SkipCount, SourceType, Fields);
		{ok, skip} -> data_pump(T, CtrlDate, Conf, Name, Middleware, update, InsertCount, UpdateCount, ErrorCount, DisabledCount, SkipCount+1, SourceType, Fields);
		{error, edisabled} -> data_pump(T, CtrlDate, Conf, Name, Middleware, update, InsertCount, UpdateCount, ErrorCount, DisabledCount+1, SkipCount, SourceType, Fields);
		_Error -> data_pump(T, CtrlDate, Conf, Name, Middleware, update, InsertCount, UpdateCount, ErrorCount+1, DisabledCount, SkipCount, SourceType, Fields)
	end.


-spec do_insert_record(tuple(), tuple(), #config{}, binary(), binary(), fs | db, list()) -> ok | {error, atom()}.
do_insert_record(Record, CtrlInsert, Conf, Name, Middleware, SourceType, Fields) when is_tuple(Record) ->
	Map = ems_util:tuple_to_maps_with_keys(Record, Fields),
	do_insert_record(Map, CtrlInsert, Conf, Name, Middleware, SourceType, Fields);
do_insert_record(Map, CtrlInsert, Conf, Name, Middleware, SourceType, _Fields) ->
	case apply(Middleware, insert_or_update, [Map, CtrlInsert, Conf, SourceType, insert]) of
		{ok, Record, Table, insert} ->
			mnesia:dirty_write(Table, Record),
			{ok, insert};
		{ok, Record, _, update} ->
			?DEBUG("~s skips data with duplicate key: ~p.", [Name, Record]),
			{ok, skip};
		{ok, skip} -> {ok, skip};
		{error, edisabled} -> {error, edisabled};
		{error, Reason} = Error ->
			ems_logger:error("~s data insert error: ~p.", [Name, Reason]),
			Error
	end.


-spec do_update_record(list(), tuple(), #config{}, binary(), binary(), fs | db, list()) -> ok | {error, atom()}.
do_update_record(Record, CtrlUpdate, Conf, Name, Middleware, SourceType, Fields) when is_tuple(Record) ->
	Map = ems_util:tuple_to_maps_with_keys(Record, Fields),
	do_update_record(Map, CtrlUpdate, Conf, Name, Middleware, SourceType, Fields);
do_update_record(Map, CtrlUpdate, Conf, Name, Middleware, SourceType, _Fields) ->
	case apply(Middleware, insert_or_update, [Map, CtrlUpdate, Conf, SourceType, update]) of
		{ok, Record, Table, Operation} ->
			mnesia:dirty_write(Table, Record),
			{ok, Operation};
		{ok, skip} -> {ok, skip};
		{error, edisabled} -> {error, edisabled};
		{error, Reason} = Error ->	
			ems_logger:error("~s data update error: ~p.", [Name, Reason]),
			Error
	end.





