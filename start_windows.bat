@echo off
setlocal
cd /d %~dp0
if not defined UTAMO_HOST set UTAMO_HOST=127.0.0.1
if not defined UTAMO_PM3_MODE set UTAMO_PM3_MODE=ANALYSIS_ONLY
if not exist .venv (
  py -3 -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat || exit /b 1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || exit /b 1
python main.py
endlocal
