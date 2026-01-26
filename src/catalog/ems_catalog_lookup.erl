%%********************************************************************
%% @title Module ems_catalog_lookup
%% @version 1.0.0
%% @doc Module responsible for catalog lookup
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_catalog_lookup).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").
-include_lib("stdlib/include/qlc.hrl").


-export([lookup/1, 
		 lookup/2,
		 find/2,  
		 all/1,
		 list_kernel_catalog/0, 
		 list_re_catalog/0]).

-spec find(ets_catalog_get_fs | ets_catalog_post_fs | ets_catalog_put_fs | ets_catalog_delete_fs | ets_catalog_options_fs | ets_catalog_kernel_fs |
		   ets_catalog_get_db | ets_catalog_post_db | ets_catalog_put_db | ets_catalog_delete_db | ets_catalog_options_db | ets_catalog_kernel_db,
		   non_neg_integer()) -> {ok, #service{}} | {error, enoent}.
find(Table, Rowid) ->
	case ets:lookup(Table, Rowid) of
		[] -> {error, enoent};
		[Record|_] -> {ok, Record}
	end.

-spec all(ets_catalog_get_fs | ets_catalog_post_fs | ets_catalog_put_fs | ets_catalog_delete_fs | ets_catalog_options_fs | ets_catalog_kernel_fs |
		   ets_catalog_get_db | ets_catalog_post_db | ets_catalog_put_db | ets_catalog_delete_db | ets_catalog_options_db | ets_catalog_kernel_db) -> list() | {error, atom()}.
all(Table) -> {ok, ets:tab2list(Table)}.

-spec lookup(#request{}) -> {error, enoent} | {#service{}, map(), map()}.
lookup(Request) ->	
	case lookup(Request, false, db) of
		{error, enoent} -> 
			case lookup(Request, false, fs) of
				{error, enoent} -> 
					case lookup(Request, true, db) of
						{error, enoent} -> lookup(Request, true, fs);
						Result -> Result
					end;
				Result -> Result
			end;			
		Result -> Result
	end.


-spec lookup(#request{}, boolean(), atom()) -> {error, enoent} | {#service{}, map(), map()}.
lookup(Request = #request{type = Type, rowid = Rowid, params_url = ParamsMap}, FindWithRE, SourceType) ->	
	Table = ems_catalog:get_table(Type, FindWithRE, SourceType),
	case FindWithRE of
		false ->
			case find(Table, Rowid) of
				{ok, Service = #service{enable = Enable}} -> 
					case Enable of
						true -> 
							Querystring = ems_util:parse_request_querystring(Service, Request),
							{Service, ParamsMap, Querystring};
						false ->
							{error, edisabled_service}
					end;
				_ -> {error, enoent}
			end;
		true ->
			case all(Table) of
				{ok, Records} ->
					case lookup_re(Request, Records) of
						{error, enoent} -> {error, enoent};
						{Service = #service{enable = Enable}, ParamsMapRE} -> 
							case Enable of
								true -> 
									Querystring = ems_util:parse_request_querystring(Service, Request),
									{Service, ParamsMapRE, Querystring};
								false ->
									{error, edisabled_service}
							end
					end;
				_ -> {error, enoent}
			end
	end.

lookup(Method, Uri) ->
	case ems_util:encode_request(Method, Uri) of
		{ok, Request} -> lookup(Request);
		Error -> Error
	end.

-spec list_kernel_catalog() -> list(tuple()).
list_kernel_catalog() ->
	Conf = ems_config:getConfig(),
	case ems_json_scan:scan_with_filter(Conf#config.cat_path_search, Conf, <<"type">>, <<"KERNEL">>) of
		{ok, CatKernel} -> 
			CatKernel2 = [ems_catalog:new_from_map(Map, Conf) || Map <- CatKernel],
			CatKernel3 = [Cat || {Reason, Cat} <- CatKernel2, Reason == ok, Cat#service.enable == true],
			CatKernel3;
		Error -> Error
	end.

list_re_catalog() ->
	case ets:lookup(ets_ems_catalog, cat) of
		[] -> {error, enoent};
		[{cat, {_, CatRE, _}}] -> CatRE
	end.
    
    
%%====================================================================
%% Internal functions
%%====================================================================

lookup_re(_, []) -> {error, enoent};
lookup_re(Request = #request{type = Type, url = Url}, [H|T]) ->
	try
		RE = H#service.id_re_compiled,
		PatternKey = ems_util:make_rowid_from_url(Url, Type),
		case re:run(PatternKey, RE, [{capture,all_names,binary}]) of
			match -> {H, #{}};
			{match, Params} -> 
				{namelist, ParamNames} = re:inspect(RE, namelist),
				ParamsMap = maps:from_list(lists:zip(ParamNames, Params)),
				{H, ParamsMap};
			nomatch -> lookup_re(Request, T);
			{error, _ErrType} -> {error, enoent}
		end
	catch 
		_Exception:_Reason -> {error, enoent}
	end.



