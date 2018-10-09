%%********************************************************************
%% @title Module ems_bus
%% @version 1.0.0
%% @doc Main Module of ErlangsMS
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_bus).

-include("../include/ems_config.hrl").

%%% API
-export([start/0, start/1, stop/0]).

%%%===================================================================
%%% API
%%%===================================================================

start(_) -> start().

start() -> 
    application:start(rfc3339),
    application:start(asn1),
    application:start(crypto),
	application:start(public_key),    
	application:start(ssl),    
    application:start(inets),
	application:start(xmerl),
	application:start(syntax_tools),
	application:start(compiler),
	application:start(parse_trans),
    application:start(odbc),
    application:start(ranch),
	application:start(cowlib),
	application:start(cowboy),
	application:start(json_rec),
	application:start(jsx),
	application:start(poolboy),
	application:start(jiffy),
	application:start(jesse),
	application:start(mochiweb),
    application:start(oauth2),
	application:start(ems_bus).
    
stop() -> 
	application:stop(ems_bus),
	application:stop(rfc3339),
	application:stop(public_key),    
	application:stop(asn1),
	application:stop(json_rec),
	application:stop(oauth2),
	application:stop(mochiweb),
	application:stop(jesse),
	application:stop(?JSON_LIB),
	application:stop(syntax_tools),
	application:stop(xmerl),
	application:stop(compiler),
	application:stop(poolboy),
	application:stop(jsx),
	application:stop(cowboy),
	application:stop(cowlib),
	application:stop(ranch),
	application:stop(odbc),
    application:stop(ssl),
    application:stop(inets),
    application:stop(crypto),
    application:stop(oauth2).
