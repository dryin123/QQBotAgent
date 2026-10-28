@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title QQBotAgent 6.0

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
    where python >nul 2>nul
    if not errorlevel 1 set "PY=python"
)

if not defined PY (
    echo.
    echo   Python 3.9+ not found.
    echo   Install: https://www.python.org/downloads/
    echo   Check "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)" >nul 2>nul
if errorlevel 1 (
    echo.
    echo   Python 3.9 or newer is required.
    echo.
    pause
    exit /b 1
)

rem ---- 1) can the service be called right now? ----
%PY% -c "import socket; socket.create_connection(('127.0.0.1',8000),timeout=0.6).close()" >nul 2>nul
if not errorlevel 1 (
    echo   Service is already running.
    goto RUN_OK
)

rem ---- 2) not callable: try to start it ----
%PY% main.py
if not errorlevel 1 goto RUN_OK

rem ---- 3) start failed: find missing libraries ----
set "MISSING="
for %%m in (fastapi uvicorn jinja2 aiohttp pydantic websockets) do (
    %PY% -c "import %%m" >nul 2>nul
    if errorlevel 1 set "MISSING=!MISSING! %%m"
)

if not defined MISSING (
    echo.
    echo   Startup failed, but no library is missing.
    echo   See datapp.log for details.
    echo.
    pause
    exit /b 1
)

echo.
echo   Startup failed. Missing runtime libraries:
for %%m in (!MISSING!) do echo     - %%m
echo.
set "CHOICE="
set /p "CHOICE=  Install the libraries above? [1] Yes  [0] No  > "
if "!CHOICE!"=="1" goto INSTALL
echo   Cancelled. Nothing was installed.
pause
exit /b 1

rem ---- 4) install after user consent, then start ----
:INSTALL
echo.
echo   Installing!MISSING! ...
echo.
%PY% -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 (
    echo.
    echo   Mirror failed, retrying with official PyPI...
    echo.
    %PY% -m pip install -r requirements.txt
)
%PY% main.py
if errorlevel 1 goto FAILED

:RUN_OK
start "" "http://127.0.0.1:8000"
echo.
echo   ============================================================
echo   QQBotAgent 6.0 服务已在后台运行
echo   访问地址:  http://127.0.0.1:8000
echo   ------------------------------------------------------------
echo   本窗口只是启动器，随时可以关闭；
echo   关闭本窗口或关闭 WebUI 页面都不会停止服务，
echo   服务会在后台持续运行。
echo.
echo   停止服务只有两种方式：
echo     1. WebUI 页面点击红色按钮「一键停止服务」
echo     2. 命令行执行:  python main.py --stop
echo   ============================================================
echo.
pause
exit /b 0

:FAILED
echo.
echo   Startup failed. See datapp.log for details.
echo.
pause
exit /b 1
