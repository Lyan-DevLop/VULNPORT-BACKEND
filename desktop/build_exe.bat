@echo off
echo ===========================================
echo   Generando ejecutable VULNPORTS (.exe)
echo ===========================================

REM Elimina builds previos
rmdir /s /q dist
rmdir /s /q build

REM Construir el ejecutable
pyinstaller ^
  --onefile ^
  --name VULNPORTS ^
  --add-data ".env;." ^
  --add-data "network.db;." ^
  --add-data "app;app" ^
  run_app.py

echo.
echo ===========================================
echo   PROCESO COMPLETADO
echo   Ejecutable generado en: dist\VULNPORTS.exe
echo ===========================================
pause
