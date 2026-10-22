@echo off
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo [X] csc.exe not found. Install .NET Framework 4.x first.
  pause
  exit /b 1
)

taskkill /f /im "二人白皇-属性修改器.exe" >nul 2>nul

"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 /win32manifest:app.manifest ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll ^
  "/out:二人白皇-属性修改器.exe" Program.cs

if errorlevel 1 (
  echo [X] Build failed.
  pause
  exit /b 1
)
echo [OK] Built: 二人白皇-属性修改器.exe
endlocal
