%%********************************************************************
%% @title Module ems_data_loader_throttle
%% @version 1.0.0
%% @doc Provides intelligent time-based throttling for data loaders
%%      to reduce system load during off-peak hours.
%% @author Everton de Vargas Agilar <evertonagilar@gmail.com>
%% @copyright ErlangMS Team
%%********************************************************************

-module(ems_data_loader_throttle).

-export([get_throttle_multiplier/0, 
         apply_throttle/1,
         get_current_hour/0]).

%% @doc Returns the throttle multiplier based on current hour
%% Schedule:
%%   06:00-20:00: 1x (normal speed)
%%   20:00-22:00: 2x (50% slower - off-peak evening)
%%   22:00-06:00: 4x (75% slower - night time)
-spec get_throttle_multiplier() -> 1 | 2 | 4.
get_throttle_multiplier() ->
    Hour = get_current_hour(),
    get_throttle_multiplier(Hour).

%% @doc Returns throttle multiplier for a specific hour
-spec get_throttle_multiplier(non_neg_integer()) -> 1 | 2 | 4.
get_throttle_multiplier(Hour) when Hour >= 6 andalso Hour < 20 ->
    1;  % Normal speed during business hours
get_throttle_multiplier(Hour) when Hour >= 20 andalso Hour < 22 ->
    2;  % 2x slower during evening (20h-22h)
get_throttle_multiplier(_Hour) ->
    4.  % 4x slower during night (22h-06h)

%% @doc Applies throttle multiplier to a timeout value
-spec apply_throttle(pos_integer()) -> pos_integer().
apply_throttle(Timeout) ->
    Multiplier = get_throttle_multiplier(),
    Timeout * Multiplier.

%% @doc Gets current hour (0-23) in local time
-spec get_current_hour() -> 0..23.
get_current_hour() ->
    {{_Year, _Month, _Day}, {Hour, _Min, _Sec}} = calendar:local_time(),
    Hour.
