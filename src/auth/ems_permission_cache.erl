%%********************************************************************
%% @title ems_permission_cache
%% @version 1.0.0
%% @doc ETS-based cache for user permission checks
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_permission_cache).

-include("include/ems_config.hrl").
-include("include/ems_schema.hrl").

-export([start/0, get/1, put/2, invalidate/1, invalidate_user/1, cleanup_expired/0, stats/0, clear/0]).

-define(CACHE_TABLE, permission_cache_ets).
-define(CACHE_TTL, 300). % 5 minutos em segundos

%% Estrutura do cache (tuple para ETS)
%% {Hash, HasPermission, CachedAt}

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
                set,                      % Cada hash é único
                public,                   % Acessível por todos os processos
                {read_concurrency, true}, % Otimiza leituras concorrentes
                {write_concurrency, true} % Otimiza escritas concorrentes
            ]),
            ems_logger:info("ems_permission_cache ETS table created."),
            ok;
        _ -> 
            ok % Já existe
    end.

%% @doc Busca permissão no cache
-spec get(integer()) -> {ok, boolean()} | {error, not_found | expired}.
get(Hash) ->
    try
        case ets:lookup(?CACHE_TABLE, Hash) of
            [{_, HasPermission, CachedAt}] ->
                Now = ems_util:get_timestamp() div 1000,
                case (Now - CachedAt) < ?CACHE_TTL of
                    true -> 
                        {ok, HasPermission};
                    false -> 
                        %% Cache expirado, remove
                        ets:delete(?CACHE_TABLE, Hash),
                        {error, expired}
                end;
            [] -> 
                {error, not_found}
        end
    catch
        _:Reason ->
            ems_logger:error("ems_permission_cache get failed. Reason: ~p.", [Reason]),
            {error, not_found}
    end.

%% @doc Armazena resultado de permissão no cache
-spec put(integer(), boolean()) -> ok.
put(Hash, HasPermission) ->
    try
        CachedAt = ems_util:get_timestamp() div 1000,
        ets:insert(?CACHE_TABLE, {Hash, HasPermission, CachedAt}),
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_permission_cache put failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Invalida permissão do cache
-spec invalidate(integer()) -> ok.
invalidate(Hash) ->
    try
        ets:delete(?CACHE_TABLE, Hash),
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_permission_cache invalidate failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Invalida todas as permissões de um usuário
%% Nota: Isso requer varrer a tabela, use com moderação
-spec invalidate_user(integer()) -> ok.
invalidate_user(_UserId) ->
    %% Por enquanto, limpa todo o cache quando precisar invalidar um usuário
    %% Alternativa: manter índice secundário UserId -> [Hashes]
    clear(),
    ok.

%% @doc Limpa entradas expiradas (executar periodicamente)
-spec cleanup_expired() -> ok.
cleanup_expired() ->
    try
        Now = ems_util:get_timestamp() div 1000,
        Cutoff = Now - ?CACHE_TTL,
        MatchSpec = [{
            {'$1', '$2', '$3'},
            [{'<', '$3', Cutoff}],  % CachedAt < Cutoff
            [true]
        }],
        NumDeleted = ets:select_delete(?CACHE_TABLE, MatchSpec),
        case NumDeleted > 0 of
            true -> ems_logger:debug("ems_permission_cache cleaned ~p expired entries.", [NumDeleted]);
            false -> ok
        end,
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_permission_cache cleanup_expired failed. Reason: ~p.", [Reason]),
            ok
    end.

%% @doc Limpa todo o cache
-spec clear() -> ok.
clear() ->
    try
        ets:delete_all_objects(?CACHE_TABLE),
        ems_logger:info("ems_permission_cache cleared all entries."),
        ok
    catch
        _:Reason ->
            ems_logger:error("ems_permission_cache clear failed. Reason: ~p.", [Reason]),
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
            memory_mb => float(Memory / 1024 / 1024),
            ttl_seconds => ?CACHE_TTL
        }
    catch
        _:_ ->
            #{size => 0, memory_bytes => 0, memory_mb => 0.0, ttl_seconds => ?CACHE_TTL}
    end.
