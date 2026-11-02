@echo off
REM ==============================================================================
REM AICTE Cyber Security Cell - One-Command Full-Stack Platform Launcher
REM Smart India Hackathon (SIH Problem Statement ID: 26106)
REM ==============================================================================

title AICTE Cyber Threat Detection & Forensic Platform (SIH 26106)
echo ==============================================================================
echo    AICTE CYBER SECURITY CELL ^| SMART INDIA HACKATHON 2026 (SIH ID: 26106)
echo    Starting Forensic Intelligence Platform (Backend + Frontend + Vault)...
echo ==============================================================================
echo.

REM Verify Python is available
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+.
    pause
    exit /b 1
)

REM Execute the unified python orchestrator
python run_platform.py

pause

