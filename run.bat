@echo off
chcp 65001 >nul
setlocal
set "PY=py"
where py >nul 2>nul || set "PY=python"
if "%~1"=="" (
  echo NeuralScan CLI
  echo.
  echo Drag and drop a .py file or a folder onto this file.
  echo Or run:  %PY% "%~dp0neuralscan-cli.py" your_file.py
  echo.
  pause
  exit /b
)
%PY% "%~dp0neuralscan-cli.py" %*
echo.
pause
