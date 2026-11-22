@echo off
chcp 65001 > nul
rem ================================================================
rem  Конвертация general (ALT11).bat -> nfqws2
rem  При необходимости поправьте путь к папке Flowseal ниже:
set "FLOWSEAL=D:\Users\TmInT\Downloads\zapret-discord-youtube-1.9.8c"
rem ================================================================

if not exist "%FLOWSEAL%\bin\winws.exe" (
    echo [!] В папке "%FLOWSEAL%" нет bin\winws.exe
    echo     Откройте этот файл блокнотом и впишите правильный путь в FLOWSEAL.
    pause
    exit /b 1
)

"%~dp0f2n.exe" "%FLOWSEAL%" "general (ALT11).bat" -o "%~dp0out" -iface eth3

echo.
echo Результат: %~dp0out  (nfqws2.conf, blobs/, lists/, REPORT.md)
pause
