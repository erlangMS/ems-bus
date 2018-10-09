%%********************************************************************
%% @title Module ems_json_scan
%% @version 1.0.0
%% @doc Module responsible for load json files
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_json_scan).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([scan/2, scan/3, scan_with_filter/4, scan_with_filter/5]).

-spec scan(string() | binary() | list(tuple()), #config{}) -> list(map()).
scan([{_NodeName, _JsonFilename}|_] = L, Conf) -> 
	{ok, lists:reverse(scan_files(L, [], Conf, undefined, undefined))};
scan(Filename, Conf) -> 
	{ok, lists:reverse(scan_file(Filename, [], "", Conf, undefined, undefined))}.
	
-spec scan(string() | binary() | list(tuple()), binary(), #config{}) -> list(map()).	
scan(Filename, RootPath, Conf) -> 
	{ok, lists:reverse(scan_file(Filename, [], RootPath, Conf, undefined, undefined))}.

-spec scan_with_filter(string() | binary() | list(tuple()), #config{}, binary(), any()) -> list(map()).
scan_with_filter([{_NodeName, _JsonFilename}|_] = L, Conf, FilterKey, FilterValue) -> 
	{ok, lists:reverse(scan_files(L, [], Conf, FilterKey, FilterValue))}.
	
-spec scan_with_filter(string() | binary() | list(tuple()), binary(), #config{}, binary(), any()) -> list(map()).	
scan_with_filter(Filename, RootPath, Conf, FilterKey, FilterValue) -> 
	{ok, lists:reverse(scan_file(Filename, [], RootPath, Conf, FilterKey, FilterValue))}.


%% internal functions

-spec scan_files(list(tuple()), list(), #config{}, binary(), any()) -> list().
scan_files([], Result, _, _, _) -> Result;
scan_files([{_NodeName, JsonFilename}|Rest], Result, Conf, FilterKey, FilterValue) ->
	RootPath = filename:dirname(JsonFilename),
	case parse_filename_path(JsonFilename, RootPath, Conf) of
		{ok, Filename} ->
			Result2 = scan_file(Filename, Result, RootPath, Conf, FilterKey, FilterValue),
			scan_files(Rest, Result2, Conf, FilterKey, FilterValue);
		{error, Filename} ->
			ems_logger:warn("ems_json_scan scan invalid file \033[01;34m~p\033[0m.", [Filename])
	end.
		
		
-spec scan_file(string() | binary(), list(map()), binary(), #config{}, binary(), any()) -> list(map()) | {error, atom()}.
scan_file(JsonFilename, Result, RootPath, Conf, FilterKey, FilterValue) ->
	case parse_filename_path(JsonFilename, RootPath, Conf) of
		{ok, Filename} ->
			CurrentDir = filename:dirname(Filename),
			case ems_util:read_file_as_map(Filename) of
				{ok, FileList} when is_list(FileList) -> 
					scan_file_entry(FileList, CurrentDir, Filename, Result, RootPath, Conf, FilterKey, FilterValue);
				{ok, FileMap} -> 
					scan_file_entry([FileMap], CurrentDir, Filename, Result, RootPath, Conf, FilterKey, FilterValue);
				{error, enoent} ->
					ems_logger:warn("ems_json_scan scan inexistent file \033[01;34m~p\033[0m.", [Filename]),
					Result;
				_ -> 
					ems_logger:warn("ems_json_scan scan invalid file \033[01;34m~p\033[0m.", [Filename]),
					Result
			end;
		{error, Filename} ->
			ems_logger:warn("ems_json_scan scan invalid file \033[01;34m~p\033[0m.", [Filename])
	end.
	
-spec scan_file_entry(list(), string(), string(), list(), binary(), #config{}, binary(), any()) -> list().
scan_file_entry([], _, _, Result, _, _, _, _) -> Result;
scan_file_entry([Map|MapTail], CurrentDir, CurrentFilenameMap, Result, RootPath, Conf, FilterKey, FilterValue) ->
	case maps:is_key(<<"file">>, Map) of
		true -> 
			case parse_filename_path(maps:get(<<"file">>, Map), CurrentDir, Conf) of
				{ok, FilenameMap} ->
					?DEBUG("ems_json_scan scan \033[01;34m~p\033[0m.", [FilenameMap]),
					Result2 = scan_file(FilenameMap, Result, RootPath, Conf, FilterKey, FilterValue),
					scan_file_entry(MapTail, CurrentDir, CurrentFilenameMap, Result2, RootPath, Conf, FilterKey, FilterValue);			
				{error, FilenameMap} ->
					ems_logger:warn("ems_json_scan scan invalid file \033[01;34m~p\033[0m.", [FilenameMap]),
					?DEBUG("~p: ~p.", [FilenameMap, Map]),
					scan_file_entry(MapTail, CurrentDir, CurrentFilenameMap, Result, RootPath, Conf, FilterKey, FilterValue)
			end;
		false -> 
			case FilterKey =/= undefined andalso maps:is_key(FilterKey, Map) andalso maps:get(FilterKey, Map) =/= FilterValue of
				true ->
					scan_file_entry(MapTail, CurrentDir, CurrentFilenameMap, Result, RootPath, Conf, FilterKey, FilterValue);
				false ->
					Map2 = Map#{<<"ctrl_path">> => CurrentDir,
								<<"ctrl_file">> => CurrentFilenameMap,
								<<"ctrl_modified">> => ems_util:timestamp_binary(ems_util:file_last_modified(CurrentFilenameMap))},
					scan_file_entry(MapTail, CurrentDir, CurrentFilenameMap, [Map2 | Result], RootPath, Conf, FilterKey, FilterValue)
			end
	end.

-spec parse_filename_path(string() | binary(), binary(), #config{}) -> {ok, string()} | {error, string()}.
parse_filename_path(JsonFilename, RootPath, #config{static_file_path = StaticFilePath}) -> 
	{ok, ems_util:parse_file_name_path(JsonFilename, StaticFilePath, RootPath)}.
	
