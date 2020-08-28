%%********************************************************************
%% @title Module ems_api_query_postgresql_parse
%% @version 1.0.0
%% @doc It provides parse api query sql server
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_api_query_db2_parse).

-export([generate_dynamic_query/3, generate_dynamic_query/6, generate_dynamic_delete/2]).

-include("../../include/ems_config.hrl").
-include("../../include/ems_schema.hrl").


parse_fields([]) -> "*";
parse_fields(Fields) -> 
	case string:tokens(string:strip(Fields), ",") of
		[] -> erlang:error(einvalid_fields);
		Fields2 -> string:join(Fields2, ",")
	end.

	    
parse_filter(<<>>) -> {"", ""};
parse_filter(<<Filter/binary>>) ->    
    case ems_util:json_decode(Filter) of
		{ok, Filter2} -> 
			parse_filter(Filter2, [], []);
		_ -> erlang:error(einvalid_filter)
	end.
parse_filter([], [], []) -> {"", ""};
parse_filter([], Filter, Params) -> 
	Filter2 = lists:flatten(lists:reverse(Filter)),
	Params2 = lists:flatten(lists:reverse(Params)),
	{"where " ++ Filter2, Params2};
parse_filter([H|T], Filter, Params) ->
	{Param, Op, Value} = parse_condition(H),
	And = filter_conjuntion(T),
	{Cond, Params2} = format_sql_condition(Param, Op, Value, And, Params),
	parse_filter(T, [Cond | Filter], Params2).

	
filter_conjuntion([]) -> "";
filter_conjuntion(_) -> " and ".

	
parse_condition({<<Param/binary>>, Value}) when is_integer(Value) -> 
	Param2 = binary_to_list(Param), 
	parse_condition(Param2, Value, sql_integer);
parse_condition({<<Param/binary>>, Value}) when is_boolean(Value) -> 
	Param2 = binary_to_list(Param), 
	parse_condition(Param2, Value, sql_boolean);
parse_condition({<<Param/binary>>, Value}) -> 
	Param2 = binary_to_list(Param), 
	Value2 = unicode:characters_to_list(Value, utf8),
	parse_condition(Param2, Value2, sql_varchar).
parse_condition(Param, Value, DataType) -> 
	{Param2, Op} = parse_name_and_operator(Param),
	{Param3, Value2} = parse_value(Param2, Value, Op, DataType),
	{Param3, Op, Value2}.	


parse_value(Param, Value, "e", DataType) when is_integer(Value) -> 
	OdbcDataType = format_odbc_data_type(Value, DataType),
	OdbcValue = [{OdbcDataType, [ Value ]}],
	{Param, OdbcValue};
parse_value(Param, Value, "e", DataType) -> 
	OdbcDataType = format_odbc_data_type(Value, DataType),
	OdbcValue = [{OdbcDataType, [ Value ]}],
	{Param, OdbcValue};
parse_value(Param, Value, "ne", DataType) -> 
	OdbcDataType = format_odbc_data_type(Value, DataType),
	OdbcValue = [{OdbcDataType, [Value]}],
	{Param, OdbcValue};
parse_value(Param, Value, "like", sql_varchar) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_varchar),
	Value2 = Value ++ "%",
	OdbcValue = [{OdbcDataType, [Value2]}],
	{Param, OdbcValue};
parse_value(Param, Value, "ilike", sql_varchar) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_varchar),
	Param2 = "lower(" ++ Param ++ ")",
	Value2 = string:to_lower(Value) ++ "%",
	OdbcValue = [{OdbcDataType, [Value2]}],
	{Param2, OdbcValue};
parse_value(Param, Value, "contains", sql_varchar) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_varchar),
	Value2 = "%" ++ Value ++ "%",
	OdbcValue = [{OdbcDataType, [Value2]}],
	{Param, OdbcValue};
parse_value(Param, Value, "icontains", sql_varchar) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_varchar),
	Param2 = "lower(" ++ Param ++ ")",
	Value2 = "%" ++ string:to_lower(Value) ++ "%",
	OdbcValue = [{OdbcDataType, [Value2]}],
	{Param2, OdbcValue};
parse_value(Param, Value, "isnull", sql_boolean) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_boolean),
	OdbcValue = [{OdbcDataType, [Value]}],
	{Param, OdbcValue};
parse_value(Param, Value, "gt", sql_integer) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_integer),
	OdbcValue = [{OdbcDataType, [Value]}],
	{Param, OdbcValue};
parse_value(Param, Value, "gte", sql_integer) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_integer),
	OdbcValue = [{OdbcDataType, [Value]}],
	{Param, OdbcValue};
parse_value(Param, Value, "lt", sql_integer) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_integer),
	OdbcValue = [{OdbcDataType, [Value]}],
	{Param, OdbcValue};
parse_value(Param, Value, "lte", sql_integer) -> 
	OdbcDataType = format_odbc_data_type(Value, sql_integer),
	OdbcValue = [{OdbcDataType, [Value]}],
	{Param, OdbcValue};
parse_value(_, _, _, _) -> 
	erlang:error(einvalid_operator_filter).

format_odbc_data_type(Value, sql_varchar) -> {sql_varchar, length(Value) + 3};
format_odbc_data_type(_Value, sql_integer) -> sql_integer;
format_odbc_data_type(_Value, sql_boolean) -> sql_boolean;
format_odbc_data_type(_, _) -> erlang:error(einvalid_odbc_data_type).

parse_name_and_operator(Param) ->
	case string:str(Param, "__") of
		Idx when Idx > 1 ->
			Name = string:sub_string(Param, 1, Idx-1),
			Op = string:to_lower(string:sub_string(Param, Idx+2)),
			case lists:member(Op, ["like", "ilike", "contains", "icontains", "e", "ne", "gt", "gte", "lt", "lte", "isnull"]) of
				true -> {Name, Op};
				_ -> throw({einvalid_param_filter, Param})
			end;
		0 -> {Param, "e"};
		_ -> throw({einvalid_param_filter, Param})
	end.


format_sql_condition(Param, "isnull", Value, And, Params) -> 
	case Value of
		[{sql_boolean,[true]}] -> Cond = lists:flatten([Param, " is null", And]);
		_ -> Cond = lists:flatten([Param, " is not null", And])
	end,
	{Cond, Params};
format_sql_condition(Param, Op, Value, And, Params) ->
	SqlOp = format_sql_operator(Op),
	Cond = lists:flatten([Param, " ", SqlOp, " ", "?", And]),
	{Cond, [Value | Params]}.


format_sql_operator("e") -> "=";
format_sql_operator("ne") -> "!=";
format_sql_operator("like") -> "like";
format_sql_operator("ilike") -> "like";
format_sql_operator("contains") -> "like";
format_sql_operator("icontains") -> "like";
format_sql_operator("gt") -> ">";
format_sql_operator("gte") -> ">=";
format_sql_operator("lt") -> "<" ;
format_sql_operator("lte") -> "<=";
format_sql_operator("isnull") -> "is null";
format_sql_operator(_) -> erlang:error(invalid_operator_filter).


parse_sort([]) -> "";
parse_sort(SortFields) -> 
	SortFields2 = string:tokens(SortFields, ","),
	"order by " ++ parse_sort(SortFields2, []).

parse_sort([], L) -> string:join(L, ",");		
parse_sort([F|Fs], L) -> 
	F2 = string:tokens(string:to_lower(F), " "),
	case length(F2) of
		2 -> 
			F3 = parse_sort_asc_desc(F, tl(F2)),
			parse_sort(Fs, [F3 | L]);
		_ -> parse_sort(Fs, [F | L])
	end.
		

parse_sort_asc_desc(F, ["asc"]) -> F;
parse_sort_asc_desc(F, ["desc"]) -> F;
parse_sort_asc_desc(_, _) -> erlang:error(invalid_sort_filter).
	


parse_limit(Limit, Offset) when Limit > 0, Offset >= 0, Limit =< ?MAX_LIMIT_API_QUERY, Offset =< ?MAX_OFFSET_API_QUERY -> ok;
parse_limit(_, _) -> erlang:error(einvalid_limit_filter).


generate_dynamic_query(FilterJson, Fields, 
					   #service_datasource{table_name = TableName, 
										   sql = undefined}, 
					   Limit, Offset, Sort) ->
	{FilterSmnt, Params} = parse_filter(FilterJson),
	FieldsSmnt = parse_fields(Fields),
	SortSmnt = parse_sort(Sort),
	parse_limit(Limit, Offset),
	SqlSmnt = lists:flatten(case Offset == 1 of
								 true -> 
										io_lib:format("select ~s from ~s ~s ~s limit ~p", 
											[FieldsSmnt, TableName, FilterSmnt, SortSmnt, Limit]);
								 _ ->   %% bastante lento se não existir índice na chave
										io_lib:format("select * from (select ~s, row_number() over (order by current_timestamp) AS _RowNumber from ~s ~s ~s) _t where _t._RowNumber between ~p and ~p", 
											[FieldsSmnt, TableName, FilterSmnt, SortSmnt, Offset, Offset+Limit-1])
							end),
	{ok, {SqlSmnt, Params}};

generate_dynamic_query(FilterJson, Fields, 
					   #service_datasource{sql = Sql}, 
					   Limit, Offset, Sort) ->
	{FilterSmnt, Params} = parse_filter(FilterJson),
	FieldsSmnt = parse_fields(Fields),
	SortSmnt = parse_sort(Sort),
	parse_limit(Limit, Offset),
	SqlSmnt = lists:flatten(case Offset == 1 of
								 true -> 
										io_lib:format("select ~s from (~s) _t ~s ~s limit ~p", 
											[FieldsSmnt, Sql, FilterSmnt, SortSmnt, Limit]);
								 _ ->   
										%% bastante lento se não existir índice na chave
										io_lib:format("select * from (select ~s, row_number() over (order by current_timestamp) AS _RowNumber from (~s) _t_sql ~s ~s) _t where _t._RowNumber between ~p and ~p", 
											[FieldsSmnt, Sql, FilterSmnt, SortSmnt, Offset, Offset+Limit-1])
							end),
	{ok, {SqlSmnt, Params}}.

generate_dynamic_query(Id, Fields, #service_datasource{table_name = TableName, 
														primary_key = PrimaryKey}) when Id > 0, Id =< ?MAX_ID_RECORD_QUERY ->
	Params = [{sql_integer, [Id]}],
	Fields2 = parse_fields(Fields),
	SqlSmnt = lists:flatten(io_lib:format("select ~s from ~s where ~s = ? limit 1", [Fields2, TableName, PrimaryKey])),
	{ok, {SqlSmnt, Params}};
generate_dynamic_query(_, _, _) -> erlang:error(einvalid_id_object).
	

generate_dynamic_delete(Id, #service_datasource{table_name = TableName, 
												primary_key = PrimaryKey}) ->
	Params = [{sql_integer, [Id]}],
	SqlSmnt = lists:flatten(io_lib:format("delete from ~s where ~s = ?", [TableName, PrimaryKey])),
	{ok, {SqlSmnt, Params}}.



