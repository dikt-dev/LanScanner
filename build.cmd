@echo off
setlocal
pushd "%~dp0"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo [ERROR] csc.exe not found. Need .NET Framework 4.x.
  popd
  pause
  exit /b 1
)
echo Compiling with %CSC%
"%CSC%" /nologo /target:winexe /codepage:65001 /optimize+ /out:LanScanner.exe /r:System.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll Scan.cs Oui.cs Prefs.cs Ui.cs RangePicker.cs
if errorlevel 1 goto fail
powershell -NoProfile -Command "Unblock-File -LiteralPath '%~dp0LanScanner.exe'" >nul 2>&1
echo.
echo Build OK -^> LanScanner.exe
popd
pause
exit /b 0
:fail
echo.
echo Build FAILED.
popd
pause
exit /b 1
