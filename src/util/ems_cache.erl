%%********************************************************************
%% @title Module ems_cache
%% @version 1.0.0
%% @doc Module for cache management.
%%      Based on solution http://inaka.net/blog/2013/03/05/ETS-simple-cache.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_cache).

-include("../include/ems_config.hrl").
-include("../include/ems_schema.hrl").

-behavior(gen_server). 

%% Server API
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/1, handle_info/2, terminate/2, code_change/3]).

-export([new/1, get/4, get/5, flush/1, flush/2, flush_future/3, flush_future/4, add/4]).

%  Armazena o estado do service. 
-record(state, {}). 

-define(SERVER, ?MODULE).

%%====================================================================
%% Server API
%%====================================================================

start(_) -> 
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
 
stop() ->
    gen_server:cast(?SERVER, shutdown).
 
 

%%====================================================================
%% gen_server callbacks
%%====================================================================
 
init([]) ->
	NewState = #state{},
    {ok, NewState}. 
    
handle_cast(shutdown, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
	{noreply, State}.
    
handle_call(_Msg, _From, State) ->
	{reply, _Msg, State}.

handle_info({expire, CacheName, Key}, State) ->
	#config{debug = Debug} = ems_config:getConfig(),
	case Debug of
		true -> 
			case ets:lookup(CacheName, Key) of
				[{Key, {_, Request, _, _, _}}] when is_record(Request, request) ->
					ems_logger:info("ems_cache: ~p entry expired. url: ~p", [CacheName, Request#request.url]);
				_ ->
					ems_logger:info("ems_cache: ~p entry expired. key: ~p", [CacheName, Key])
			end;
		_ -> ok
	end,
	flush(CacheName, Key),
	{noreply, State};
  
handle_info({expire, CacheName, Key, FunAfterFlush}, State) ->
	#config{debug = Debug} = ems_config:getConfig(),
	case Debug of
		true -> 
			case ets:lookup(CacheName, Key) of
				[{Key, {_, Request, _, _, _}}] when is_record(Request, request) ->
					ems_logger:info("ems_cache: ~p entry expired (with callback). url: ~p", [CacheName, Request#request.url]);
				_ ->
					ems_logger:info("ems_cache: ~p entry expired (with callback). key: ~p", [CacheName, Key])
			end;
		_ -> ok
	end,
	case ets:lookup(CacheName, Key) of
		[] -> ok;
		_ -> 
			flush(CacheName, Key),
			FunAfterFlush(Key)
	end,
	{noreply, State};

handle_info(_Msg, State) ->
   {noreply, State}.

handle_info(State) ->
   {noreply, State}.

terminate(_Reason, _State) ->
    ok.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
    
    
%%====================================================================
%% Funções internas
%%====================================================================

%% @doc Check if object size is within limits
should_cache_object(Value) ->
	Size = erts_debug:size(Value) * 8,  % Convert words to bytes
	case Size =< ?CACHE_MAX_OBJECT_SIZE of
		true -> {ok, Size};
		false -> {too_large, Size}
	end.

%% @doc Cap TTL to maximum allowed
cap_ttl(infinity) -> infinity;
cap_ttl(TTL) when TTL > ?CACHE_MAX_TTL ->
	ems_logger:info("ems_cache: TTL capped from ~pms to ~pms", [TTL, ?CACHE_MAX_TTL]),
	?CACHE_MAX_TTL;
cap_ttl(TTL) -> TTL.

%% @doc Check if cache can accept more entries. If full, evict some entries.
can_add_entry(CacheName) ->
	case ets:info(CacheName, size) of
		undefined -> false;  % Cache doesn't exist
		Size when Size >= ?CACHE_MAX_ENTRIES -> 
			ems_logger:info("ems_cache: ~p reached max entries (~p), starting eviction...", [CacheName, ?CACHE_MAX_ENTRIES]),
			evict_entries(CacheName, round(?CACHE_MAX_ENTRIES * 0.1) + 1),
			true;
		_ -> true
	end.

%% @doc Evict N entries from the cache using ETS first/next (pseudo-random for set)
evict_entries(_CacheName, 0) -> ok;
evict_entries(CacheName, N) ->
	case ets:first(CacheName) of
		'$end_of_table' -> ok;
		Key ->
			ets:delete(CacheName, Key),
			evict_entries(CacheName, N - 1)
	end.

%% @doc Initializes a cache.
-spec init(string()) -> ok.
new(CacheName) ->
	ets:new(CacheName, [named_table, 
						{read_concurrency, true}, 
						 public, 
						{write_concurrency, true}]),
	ok.

%% @doc Deletes the keys that match the given ets:matchspec() from the cache.
-spec flush(string(), term()) -> true.
flush(CacheName, Key) ->
	ets:delete(CacheName, Key).

%% @doc Deletes the keys that match the given ets:matchspec() from the cache.
-spec flush_future(string(), pos_integer(), term()) -> true.
flush_future(_, infinity, _) -> 
	ok;
flush_future(CacheName, LifeTime, Key) ->
	erlang:send_after(LifeTime, ems_cache, {expire, CacheName, Key}),
	ok.

flush_future(_, infinity, _, _) -> ok;
flush_future(CacheName, LifeTime, Key, FunAfterFlush) ->
	erlang:send_after(LifeTime, ems_cache, {expire, CacheName, Key, FunAfterFlush}),
	ok.


%% @doc Deletes all keys in the given cache.
-spec flush(string()) -> true.
flush(CacheName) ->
	true = ets:delete_all_objects(CacheName).

%% @doc Tries to lookup Key in the cache, and execute the given FunResult
%% on a miss.
-spec get(string(), infinity|pos_integer(), term(), function()) -> term().
get(_CacheName, 0, _Key, FunResult) ->
	FunResult();

get(CacheName, {PositiveLifeTime, NegativeLifeTime}, Key, FunResult) ->
	case ets:lookup(CacheName, Key) of
		[] ->
		  % Not found, create it.
		  V = FunResult(),
		  LifeTime = case V of
						 [] -> NegativeLifeTime;
						 _ -> PositiveLifeTime
					 end,
		  % Validate size and entry limit before caching
		  case {should_cache_object(V), can_add_entry(CacheName), LifeTime > 0} of
			  {{ok, _Size}, true, true} ->
				  CappedTTL = cap_ttl(LifeTime),
				  ets:insert(CacheName, {Key, V}),
				  flush_future(CacheName, CappedTTL, Key);
			  {{too_large, Size}, _, _} ->
				  ems_logger:warn("ems_cache: object too large (~p bytes) for ~p, not caching", [Size, CacheName]);
			  {_, false, _} ->
				  ok;  % Entry limit reached, don't cache
			  {_, _, false} ->
				  ok
		  end,
		  V;
		[{Key, R}] -> R
	end;

get(CacheName, LifeTime, Key, FunResult) ->
	case ets:lookup(CacheName, Key) of
		[] ->
		  % Not found, create it.
		  V = FunResult(),
		  % Validate size and entry limit before caching
		  case {should_cache_object(V), can_add_entry(CacheName)} of
			  {{ok, _Size}, true} ->
				  CappedTTL = cap_ttl(LifeTime),
				  ets:insert(CacheName, {Key, V}),
				  flush_future(CacheName, CappedTTL, Key);
			  {{too_large, Size}, _} ->
				  ems_logger:warn("ems_cache: object too large (~p bytes) for ~p, not caching", [Size, CacheName]);
			  {_, false} ->
				  ok  % Entry limit reached, don't cache
		  end,
		  V;
		[{Key, R}] -> R
	end.

get(CacheName, LifeTime, Key, FunResult, FunAfterFlush) when is_function(FunAfterFlush) ->
	case ets:lookup(CacheName, Key) of
		[] ->
		  % Not found, create it.
		  V = FunResult(),
		  % Validate size and entry limit before caching
		  case {should_cache_object(V), can_add_entry(CacheName)} of
			  {{ok, _Size}, true} ->
				  CappedTTL = cap_ttl(LifeTime),
				  ets:insert(CacheName, {Key, V}),
				  flush_future(CacheName, CappedTTL, Key, FunAfterFlush);
			  {{too_large, Size}, _} ->
				  ems_logger:warn("ems_cache: object too large (~p bytes) for ~p, not caching", [Size, CacheName]);
			  {_, false} ->
				  ok  % Entry limit reached, don't cache
		  end,
		  V;
		[{Key, R}] -> R
	end.

add(CacheName, LifeTime, Key, Value) ->
  % Validate size and entry limit before caching
  case {should_cache_object(Value), can_add_entry(CacheName)} of
	  {{ok, _Size}, true} ->
		  CappedTTL = cap_ttl(LifeTime),
		  ets:insert(CacheName, {Key, Value}),
		  flush_future(CacheName, CappedTTL, Key),
		  ok;
	  {{too_large, Size}, _} ->
		  ems_logger:warn("ems_cache: object too large (~p bytes) for ~p, not caching", [Size, CacheName]),
		  {error, too_large};
	  {_, false} ->
		  {error, cache_full}
  end.
  
