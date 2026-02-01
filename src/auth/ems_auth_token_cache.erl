%%********************************************************************
%% @title ems_auth_token_cache
%% @version 1.0.0
%% @doc ETS-based cache for validated OAuth2 access tokens
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_auth_token_cache).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([start/0, get/1, put/6, invalidate/1, cleanup_expired/0, stats/0, clear/0]).

-define(CACHE_TABLE, auth_token_cache_ets).

%% Estrutura do cache (tuple para ETS)
%% {TokenHash, Client, User, Scope, State, ExpiryTime, CachedAt}

%%====================================================================
%% API
%%====================================================================

%% @doc Inicia a tabela ETS
-spec start() -> ok.
start() ->
    case ets:info(?CACHE_TABLE) of
        undefined ->
            ets:new(?CACHE_TABLE, [
                named_table,
                set,                      % Cada token é único
                public,                   % Acessível por todos os processos
                {read_concurrency, true}, % Otimiza leituras concorrentes
                {write_concurrency, true} % Otimiza escritas concorrentes
            ]),
            ems_logger:info("ems_auth_token_cache ETS table created."),
            ok;
        _ -> 
            ok % Já existe
    end.

%% @doc Busca token no cache
-spec get(binary()) -> {ok, {term(), term(), binary(), binary(), integer()}} | {error, not_found | expired}.
get(AccessToken) ->
    try
        TokenHash = crypto:hash(sha256, AccessToken),
        case ets:lookup(?CACHE_TABLE, TokenHash) of
            [{_, Client, User, Scope, State, ExpiryTime, _CachedAt}] ->
                Now = ems_util:get_timestamp() div 1000,
                case ExpiryTime > Now of
                    true -> 
                        {ok, {Client, User, Scope, State, ExpiryTime}};
                    false -> 
                        %% Token expirado, remove do cache
                        ets:delete(?CACHE_TABLE, TokenHash),
                        {error, expired}
                end;
            [] -> 
                {error, not_found}
        end
    catch
        _:Reason ->
            ems_logger:error("ems_auth_token_cache get failed. Reason: ~p.", [Reason]),
            {error, not_found}
    end.

%% @doc Armazena token validado no cache
-spec put(binary(), term(), term(), binary(), binary(), integer()) -> ok.
put(AccessToken, Client, User, Scope, State, ExpiryTime) ->
    try
        TokenHash = crypto:hash(sha256, AccessToken),
        CachedAt = ems_util:get_timestamp() div 1000,
        ets:insert(?CACHE_TABLE, {TokenHash, Client, User, Scope, State, ExpiryTime, CachedAt}),
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_auth_token_cache put failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Invalida token do cache
-spec invalidate(binary()) -> ok.
invalidate(AccessToken) ->
    try
        TokenHash = crypto:hash(sha256, AccessToken),
        ets:delete(?CACHE_TABLE, TokenHash),
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_auth_token_cache invalidate failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Limpa tokens expirados (executar periodicamente)
-spec cleanup_expired() -> ok.
cleanup_expired() ->
    try
        Now = ems_util:get_timestamp() div 1000,
        MatchSpec = [{
            {'$1', '$2', '$3', '$4', '$5', '$6', '$7'},
            [{'<', '$6', Now}],  % ExpiryTime < Now
            [true]
        }],
        NumDeleted = ets:select_delete(?CACHE_TABLE, MatchSpec),
        case NumDeleted > 0 of
            true -> ems_logger:debug("ems_auth_token_cache cleaned ~p expired tokens.", [NumDeleted]);
            false -> ok
        end,
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_auth_token_cache cleanup_expired failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Limpa todo o cache
-spec clear() -> ok.
clear() ->
    try
        ets:delete_all_objects(?CACHE_TABLE),
        ems_logger:info("ems_auth_token_cache cleared all tokens."),
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_auth_token_cache clear failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Estatísticas do cache
-spec stats() -> map().
stats() ->
    try
        Size = ets:info(?CACHE_TABLE, size),
        Memory = ets:info(?CACHE_TABLE, memory) * erlang:system_info(wordsize),
        #{
            size => Size,
            memory_bytes => Memory,
            memory_mb => float(Memory / 1024 / 1024)
        }
    catch
        _:_ ->
            #{size => 0, memory_bytes => 0, memory_mb => 0.0}
    end.
