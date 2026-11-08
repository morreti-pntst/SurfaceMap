@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "PATH=%ProgramFiles%\Docker\Docker\resources\bin;%PATH%"
set "env_option="
if exist ".env" set "env_option=--env-file .env"
docker compose -f compose.yaml %env_option% down --remove-orphans
set "result=%errorlevel%"
if "%result%"=="0" (
    echo SurfaceMap stopped. Its port is released and project data is kept.
) else (
    echo SurfaceMap could not confirm shutdown. Review the Docker output above.
)
popd
if /i not "%~1"=="--no-pause" pause
exit /b %result%
