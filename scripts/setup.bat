@echo off
REM Idempotent local bootstrap for VulnVista (Windows equivalent of setup.sh).
REM - Creates the host-backed persistent storage directories.
REM - Copies .env.example to .env if .env doesn't exist yet.
REM - Pre-creates the shared Docker network so lab\docker-compose.yml can be
REM   started independently of the root stack's startup order.
setlocal enableextensions

pushd "%~dp0.."
if errorlevel 1 (
  echo ERROR: could not switch to the repository root.
  exit /b 1
)

for %%D in ("storage\postgres" "storage\uploads" "storage\lab\juice-shop") do (
  if not exist "%%~D" (
    mkdir "%%~D"
    if errorlevel 1 (
      echo ERROR: failed to create %%~D
      popd
      exit /b 1
    )
  )
)
echo Storage directories ready under .\storage

if not exist ".env" (
  if not exist ".env.example" (
    echo ERROR: .env.example not found, cannot create .env.
    popd
    exit /b 1
  )
  copy /y ".env.example" ".env" >nul
  if errorlevel 1 (
    echo ERROR: failed to copy .env.example to .env
    popd
    exit /b 1
  )
  echo Created .env from .env.example - review it before running docker compose up.
) else (
  echo .env already exists, leaving it as-is.
)

where docker >nul 2>&1
if errorlevel 1 (
  echo ERROR: docker was not found on PATH. Install Docker Desktop and retry.
  popd
  exit /b 1
)

docker network inspect vulnvista_net >nul 2>&1
if errorlevel 1 (
  docker network create vulnvista_net
  if errorlevel 1 (
    echo ERROR: failed to create Docker network vulnvista_net. Is Docker Desktop running?
    popd
    exit /b 1
  )
  echo Created Docker network vulnvista_net
) else (
  echo Docker network vulnvista_net already exists.
)

echo Setup complete. Next: docker compose up --build
popd
exit /b 0
