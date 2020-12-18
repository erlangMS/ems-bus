%%********************************************************************
%% @title Module ems_api_query_mnesia
%% @version 1.0.0
%% @doc It provides api query functions for access mnesia data
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_api_query_mnesia).

-export([find/6, find_by_id/3, find_by_owner/7]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

find(FilterJson, Fields, Limit, Offset, Sort, Datasource = #service_datasource{table_name = TableName, 
																			   remap_fields_rev = RemapFieldsRev,
																			   show_remap_fields = ShowRemapFields}) ->
	case ems_api_query_mnesia_parse:generate_dynamic_query(FilterJson, Fields, Datasource, Limit, Offset, Sort) of
		{ok, {FieldList, FilterList, _LimitSmnt}} -> 
			case ems_db:find(TableName, FieldList, FilterList, Limit, Offset) of
				{ok, Result} -> 
					case RemapFieldsRev == undefined of
						true -> ResultJson = ems_schema:to_json(Result);
						false -> ResultJson = ems_schema:to_json(remap_fields(Result, RemapFieldsRev, ShowRemapFields, []))
					end;
				_ -> 
					ResultJson = ?EMPTY_LIST_JSON
			end,
			{ok, ResultJson};
		{error, Reason} -> {error, Reason}
	end.


find_by_id(Id, Fields, Datasource = #service_datasource{table_name = TableName,
														remap_fields_rev = RemapFieldsRev,
														show_remap_fields = ShowRemapFields}) ->
	case ems_api_query_mnesia_parse:generate_dynamic_query(Id, Fields, Datasource) of
		{ok, FieldList} -> 
			case ems_db:find_by_id(TableName, Id, FieldList) of
				{ok, Result} ->	
					case RemapFieldsRev == undefined of
						true -> ResultJson = ems_schema:to_json(Result);
						false -> 
							[Result2] = remap_fields([Result], RemapFieldsRev, ShowRemapFields, []),
							ResultJson = ems_schema:to_json(Result2)
					end;
				_ -> ResultJson = ?ENOENT_JSON
			end,
			{ok, ResultJson};
		{error, Reason} -> {error, Reason}
	end.

find_by_owner(FilterJson, Fields, Limit, Offset, Sort, IdOwner, Datasource = #service_datasource{table_name = TableName, 
																								 foreign_key = ForeignKey, 
																								 foreign_table_name = ForeignTableName,
																								 primary_key = PrimaryKey}) ->
	case ems_db:get(ForeignTableName, IdOwner) of
		{ok, Owner} ->
			case ems_api_query_mnesia_parse:generate_dynamic_query(FilterJson, Fields, Datasource, Limit, Offset, Sort) of
				{ok, {FieldList, FilterList, _LimitSmnt}} -> 
					case PrimaryKey of
						undefined -> ForeignKeyValue = IdOwner;
						_ -> 
							case is_list(TableName) of
								true -> 
									TableName2 = hd(TableName),
									TabFieldNames = mnesia:table_info(TableName2, attributes);
								false -> 
									TabFieldNames = mnesia:table_info(TableName, attributes)
							end,
							FieldPosition = ems_db:field_position(PrimaryKey, TabFieldNames, 2),
							ForeignKeyValue = element(FieldPosition, Owner)
					end,
					FilterList2 = [{ForeignKey, <<"==">>, ForeignKeyValue} | FilterList],
					case ems_db:find(TableName, FieldList, FilterList2, Limit, Offset) of
						{ok, Result} -> ResultJson = ems_schema:to_json(Result);
						_ -> ResultJson = ?ENOENT_JSON
					end,
					{ok, ResultJson};
				{error, Reason} -> {error, Reason}
			end;
		_ -> {error, enoent}
	end.

remap_fields([], _, _, Result) -> Result;
remap_fields([MapH|MapT], RemapFields, ShowRemapFields, Result) ->
	Record = maps:to_list(MapH),
	Record2 = remap_fields_record(Record, RemapFields, ShowRemapFields, []),
	Map = maps:from_list(Record2),
	remap_fields(MapT, RemapFields, ShowRemapFields, [Map|Result]).
	

-spec remap_fields_record(list(), map(), boolean(), list()) -> list().
remap_fields_record([], _, _, Result) -> Result;
remap_fields_record([{K,V}|T], RemapFields, true, Result) ->
	RemapField = {maps:get(K, RemapFields, K), V},
	remap_fields_record(T, RemapFields, true, [RemapField|[{K,V}|Result]]);
remap_fields_record([{K,V}|T], RemapFields, false, Result) ->
	RemapField = {maps:get(K, RemapFields, K), V},
	remap_fields_record(T, RemapFields, false, [RemapField|Result]).


