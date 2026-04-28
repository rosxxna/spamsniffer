@echo off
setlocal

where py >nul 2>nul
if %errorlevel%==0 (
    py main.py
    goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
    python main.py
    goto :eof
)

echo Python was not found on this machine.
echo Install Python 3.10+ and make sure "python" or "py" is available in PATH.
pause
