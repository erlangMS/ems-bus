%%********************************************************************
%% @title Module ems_api_query_sqlserver
%% @version 1.0.0
%% @doc It provides api query functions for odbc database.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_api_query_sqlserver).

-export([find/6, find_by_id/3, delete/2]).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").


find(FilterJson, Fields, Limit, Offset, Sort, Datasource) ->
	case ems_api_query_sqlserver_parse:generate_dynamic_query(FilterJson, Fields, Datasource, Limit, Offset, Sort) of
		{ok, {Sql, Params}} -> 
			execute_dynamic_query(Sql, Params, Datasource);
		{error, Reason} -> {error, Reason}
	end.


find_by_id(Id, Fields, Datasource) ->
	case ems_api_query_sqlserver_parse:generate_dynamic_query(Id, Fields, Datasource) of
		{ok, {Sql, Params}} -> execute_dynamic_query(Sql, Params, Datasource);
		{error, Reason} -> {error, Reason}
	end.

delete(Id, Datasource) ->
	case ems_api_query_sqlserver_parse:generate_dynamic_delete(Id, Datasource) of
		{ok, {Sql, Params}} -> execute_dynamic_query(Sql, Params, Datasource);
		{error, Reason} -> {error, Reason}
	end.

execute_dynamic_query(Sql, Params, Datasource) ->
	try
		io:format("ems_api_query_sqlserver execute sql: ~s. Params: ~p.", [Sql, Params]),
		case ems_odbc_pool:param_query(Datasource, Sql, Params, ?MAX_TIME_ODBC_QUERY) of
			{_, Fields, Records} -> 
				Objects = ems_util:json_encode_table(Fields, Records),
				%io:format("~p", [Objects]),
				{ok, Objects};
			{error, Reason} -> {error, Reason}
		end
	catch
		_Exception:Reason2 -> {error, Reason2}
	end.
	    
