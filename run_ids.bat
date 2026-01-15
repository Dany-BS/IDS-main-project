@echo off
:: Check for admin privileges and relaunch if needed
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

echo Starting Intrusion Detection System...

:: Change to the script directory
cd /d "%~dp0"

:: Add the project root to PYTHONPATH
set PYTHONPATH=%~dp0..;%PYTHONPATH%

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python and add it to your PATH
    pause
    exit /b 1
)

:: Check if required packages are already installed
echo Checking required dependencies...
python -c "import scapy" >nul 2>&1
set SCAPY_MISSING=%ERRORLEVEL%
python -c "import wmi" >nul 2>&1
set WMI_MISSING=%ERRORLEVEL%
python -c "import customtkinter" >nul 2>&1
set CTK_MISSING=%ERRORLEVEL%

:: Only install missing packages
if %SCAPY_MISSING% neq 0 set MISSING_PKGS=scapy
if %WMI_MISSING% neq 0 set MISSING_PKGS=%MISSING_PKGS% wmi
if %CTK_MISSING% neq 0 set MISSING_PKGS=%MISSING_PKGS% customtkinter

if defined MISSING_PKGS (
    echo Installing missing dependencies: %MISSING_PKGS%
    python -m pip install --upgrade pip --user
    python -m pip install %MISSING_PKGS% --user
) else (
    echo All required dependencies are already installed
)

:: Check if Npcap is installed
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Npcap" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo WARNING: Npcap is not installed!
    echo Please download and install Npcap from https://npcap.com/#download
    echo Make sure to check "Install Npcap in WinPcap API-compatible Mode" during installation
    echo.
    echo Press any key to open the Npcap download page...
    pause >nul
    start https://npcap.com/#download
    echo Please run this script again after installing Npcap
    pause
    exit /b 1
)

:: Try to run the script
echo Launching IDS application...
python main.py
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to launch application
    echo Please check if all required files are present and you have necessary permissions
    pause
    exit /b 1
)

pause
exit /b 0

