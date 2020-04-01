@echo off
cls
echo Copiando dependencia jiffy para deps...
xcopy /e /q /y deps_win\jiffy\* deps\jiffy\
echo Build ems-bus with rebar...
if not exist priv\log goto DeleteDBFolder
rmdir /S /Q priv\log
:DeleteDBFolder
if not exist priv\db goto BuildWithRebar
rmdir /S /Q priv\db
:BuildWithRebar
tools\rebar\rebar clean get-deps compile --config rebar_win.config


