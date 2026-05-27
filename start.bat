@echo off
echo PhishGuard – Starting...
pip install flask werkzeug --quiet

REM Only wipe DB if --reset flag is passed
if "%1"=="--reset" (
  echo Resetting database...
  del training.db 2>nul
)

python app.py
pause
