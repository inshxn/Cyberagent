@echo off
setlocal
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
)
if "%BACKEND_PORT%"=="" set BACKEND_PORT=8000
call .venv\Scripts\activate
pip install -r requirements.txt
where npm >nul 2>nul
if %errorlevel%==0 (
  cd xpulse\frontend
  npm install
  npm run build
  cd ..\..
)
uvicorn api.server:app --host 0.0.0.0 --port %BACKEND_PORT%
