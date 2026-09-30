@echo off
rem Sirve EML Inspector en http://localhost:8000 y lo abre en el navegador.
cd /d "%~dp0"
start "" /b cmd /c "timeout /t 2 >nul & start "" http://localhost:8000/"
where py >nul 2>nul && (py -m http.server 8000 --bind 127.0.0.1 & goto :eof)
where python >nul 2>nul && (python -m http.server 8000 --bind 127.0.0.1 & goto :eof)
where npx >nul 2>nul && (npx --yes http-server -p 8000 -a 127.0.0.1 -c-1 & goto :eof)
echo No se encontro Python ni Node. Abre index.html directamente (la IA local puede no funcionar).
pause
