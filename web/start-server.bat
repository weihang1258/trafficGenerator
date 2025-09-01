@echo off
echo 启动HTTP服务器...
cd /d "%~dp0\static"
echo 当前目录: %CD%
echo 访问地址: http://localhost:8080/index-redesigned.html
py -3 -m http.server 8080
pause