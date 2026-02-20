%%********************************************************************
%% @title Module ems_tarpit
%% @version 1.0.0
%% @doc Centralized tarpit mechanism with concurrency-safe semaphore.
%%
%% Both tarpit_leve/0 and tarpit_hard/0 share a single atomic counter
%% that limits the maximum number of concurrent blocked threads to
%% ?HTTP_TARPIT_MAX_BLOCKED. When the limit is reached, the request is
%% released immediately to prevent Cowboy worker pool exhaustion under
%% flood attacks.
%%
%% Usage:
%%   - tarpit_leve/0 : soft delay (service not found, minor probes)
%%   - tarpit_hard/0 : hard delay (malicious URLs, scanner attacks)
%%
%% Initialization:
%%   Call ems_tarpit:init/0 once at application startup.
%%
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_tarpit).

-include("include/ems_config.hrl").

-export([init/0, tarpit_leve/0, tarpit_hard/0]).

-define(COUNTER_KEY, ems_tarpit_active_counter).


%%====================================================================
%% API
%%====================================================================

%% @doc Initialize the tarpit semaphore counter.
%% Must be called once at application startup (ems_bus_app:start/2).
init() ->
    Ref = atomics:new(1, [{signed, false}]),
    persistent_term:put(?COUNTER_KEY, Ref),
    ok.

%% @doc Soft tarpit — for service-not-found and minor probe requests.
%% Delay: ?HTTP_TARPIT_SOFT_DELAY ms (e.g. 2 seconds).
tarpit_leve() ->
    do_tarpit(?HTTP_TARPIT_SOFT_DELAY).

%% @doc Hard tarpit — for malicious URLs, URI too long, unsupported HTTP methods.
%% Delay: ?HTTP_TARPIT_DELAY ms (e.g. 30 seconds).
tarpit_hard() ->
    do_tarpit(?HTTP_TARPIT_DELAY).


%%====================================================================
%% Internal functions
%%====================================================================

%% @doc Core tarpit logic with semaphore guard.
%% Atomically acquires a slot before sleeping. Always releases on exit
%% (even if the process is killed) via try/after.
%% If all slots are occupied, skips the sleep and returns immediately.
do_tarpit(Delay) ->
    Ref = get_counter(),
    N = atomics:add_get(Ref, 1, 1),
    if N =< ?HTTP_TARPIT_MAX_BLOCKED ->
        try
            catch timer:sleep(Delay)
        after
            atomics:sub(Ref, 1, 1)
        end;
    true ->
        % Semaphore full — release immediately to protect the worker pool
        atomics:sub(Ref, 1, 1)
    end.

%% @doc Returns the shared atomic counter reference.
%% Initializes lazily on first access (safe for concurrent callers).
get_counter() ->
    case persistent_term:get(?COUNTER_KEY, undefined) of
        undefined ->
            % First call before explicit init — initialize defensively
            Ref = atomics:new(1, [{signed, false}]),
            persistent_term:put(?COUNTER_KEY, Ref),
            Ref;
        Ref ->
            Ref
    end.
