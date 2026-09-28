@ECHO OFF
SETLOCAL

:: cert info to use for signing
SET TSAURL=http://time.certum.pl/
SET LIBNAME=Crypture
SET LIBURL=https://github.com/NoMoreFood/Crypture

:: setup environment variables based on location of this script
SET BASEDIR=%~dp0.
SET BINDIR=%~dp0..\bin\Release
SET OUTDIR=%~dp0..\..\Binaries
SET STAGEDIR=%~dp0PackageStage

POWERSHELL -NoProfile -File "%BASEDIR%\Build.ps1" -BinaryDirectory "%BINDIR%" ^
    -OutputDirectory "%OUTDIR%" -StageDirectory "%STAGEDIR%" ^
    -TimestampUrl "%TSAURL%" -ProductName "%LIBNAME%" -ProductUrl "%LIBURL%"
EXIT /B %ERRORLEVEL%
