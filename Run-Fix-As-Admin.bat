@echo off
chcp 65001 >nul 2>&1
rem Self-elevating launcher for Fix-ClashVergeTunACL.ps1
net session >nul 2>&1
if %errorlevel% EQU 0 goto :iamadmin
echo Requesting administrator elevation...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
goto :eof

:iamadmin
echo Running as administrator, fixing C:\ root ACL...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix-ClashVergeTunACL.ps1"
echo.
echo Exit code: %errorlevel%
pause
