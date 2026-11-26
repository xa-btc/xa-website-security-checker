@echo off
setlocal
cd /d "%~dp0"

rem Find Python without depending on Explorer's inherited PATH.
set "WT_PYTHON="
set "WT_PY_ARGS="
if exist "%~dp0.venv\Scripts\python.exe" call :try_python "%~dp0.venv\Scripts\python.exe"
for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do if exist "%%~fD\python.exe" call :try_python "%%~fD\python.exe"
for /d %%D in ("%LocalAppData%\Python\pythoncore-3*") do if exist "%%~fD\python.exe" call :try_python "%%~fD\python.exe"
if not defined WT_PYTHON if exist "%SystemRoot%\py.exe" call :try_python "%SystemRoot%\py.exe" -3
if not defined WT_PYTHON call :try_python py.exe -3
if not defined WT_PYTHON call :try_python python.exe
if not defined WT_PYTHON goto :missing_python

"%WT_PYTHON%" %WT_PY_ARGS% -B "%~dp0start.py" %*
set "WT_EXIT_CODE=%errorlevel%"
if not "%WT_EXIT_CODE%"=="0" pause
exit /b %WT_EXIT_CODE%

:try_python
if defined WT_PYTHON exit /b 0
"%~1" %~2 -I -B -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
set "WT_PYTHON=%~1"
set "WT_PY_ARGS=%~2"
exit /b 0

:missing_python
echo Python 3.10 or newer could not be found.
echo Install Python from https://www.python.org/downloads/windows/ and run this launcher again.
pause
exit /b 1
