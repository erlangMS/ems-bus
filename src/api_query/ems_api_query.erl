%%********************************************************************
%% @title Module ems_api_query
%% @version 1.0.0
%% @doc It provides API query functions
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_api_query).

-export([find/6, find_by_id/3, find_by_owner/7, insert/3, update/4, delete/3]).

-include("include/ems_schema.hrl").


find(FilterJson, Fields, Limit, Offset, Sort, Datasource = #service_datasource{type = ConnType}) ->
	try
		case ConnType of
			db2 -> ems_api_query_db2:find(FilterJson, Fields, Limit, Offset, Sort, Datasource); 
			postgresql -> ems_api_query_postgresql:find(FilterJson, Fields, Limit, Offset, Sort, Datasource); 
			sqlserver -> ems_api_query_sqlserver:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			sqlite -> ems_api_query_sqlite:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			mnesia -> ems_api_query_mnesia:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			_ -> erlang:error(einvalid_datasource_type)
		end
	catch
		_Exception:Reason -> {error, Reason}
	end.


find_by_owner(FilterJson, Fields, Limit, Offset, Sort, IdOwner, Datasource = #service_datasource{type = ConnType}) ->
	try
		case ConnType of
			db2 -> ems_api_query_db2:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			postgresql -> ems_api_query_postgresql:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			sqlserver -> ems_api_query_sqlserver:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			sqlite -> ems_api_query_sqlite:find(FilterJson, Fields, Limit, Offset, Sort, Datasource);
			mnesia -> ems_api_query_mnesia:find_by_owner(FilterJson, Fields, Limit, Offset, Sort, IdOwner, Datasource);
			_ -> erlang:error(einvalid_datasource_type)
		end
	catch
		_Exception:Reason -> {error, Reason}
	end.


find_by_id(Id, Fields, Datasource =  #service_datasource{type = ConnType}) ->
	try
		case ConnType of
			db2 -> ems_api_query_db2:find_by_id(Id, Fields, Datasource);
			postgresql -> ems_api_query_postgresql:find_by_id(Id, Fields, Datasource);
			sqlserver -> ems_api_query_sqlserver:find_by_id(Id, Fields, Datasource);
			sqlite -> ems_api_query_sqlite:find_by_id(Id, Fields, Datasource);
			mnesia -> ems_api_query_mnesia:find_by_id(Id, Fields, Datasource);
			_ -> erlang:error(einvalid_datasource_type)
		end
	catch
		_Exception:Reason -> {error, Reason}
	end.
		
		
insert(Payload, Service, Datasource = #service_datasource{type = ConnType}) ->
	try
		case ConnType of
			db2 -> ok;
			postgresql -> ok;
			sqlserver -> ok;
			sqlite -> ok;
			mnesia -> ems_api_query_mnesia:insert(Payload, Service, Datasource);
			_ -> erlang:error(einvalid_datasource_type)
		end
	catch
		_Exception:Reason -> {error, Reason}
	end.
		

update(Id, Payload, Service, Datasource = #service_datasource{type = ConnType}) ->
	try
		case maps:is_key(<<"id">>, Payload) of
			true -> {error, eupdate_id_not_allowed};
			_ ->
				case ConnType of
					db2 -> ok;
					postgresql -> ok;
					sqlserver -> ok;
					sqlite -> ok;
					mnesia -> ems_api_query_mnesia:update(Id, Payload, Service, Datasource);
					_ -> erlang:error(einvalid_datasource_type)
				end
		end
	catch
		_Exception:Reason -> {error, Reason}
	end.
		

delete(Id, Service, Datasource = #service_datasource{type = ConnType}) -> 
	try
		case ConnType of
			db2 -> ems_api_query_db2:delete(Id, Datasource); 
			postgresql -> ems_api_query_postgresql:delete(Id, Datasource); 
			sqlserver -> ems_api_query_sqlserver:delete(Id, Datasource);
			sqlite -> ok;
			mnesia -> ems_api_query_mnesia:delete(Id, Service, Datasource);
			_ -> erlang:error(einvalid_datasource_type)
		end
	catch
		_Exception:Reason -> {error, Reason}
	end.
		

