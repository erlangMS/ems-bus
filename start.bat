@echo off
erl -pa ..\msbus\ebin deps\jsx\ebin deps\poolboy\ebin -sname msbus -setcookie erlangms -eval "application:start(msbus)" -boot start_sasl -config .\priv\conf\elog