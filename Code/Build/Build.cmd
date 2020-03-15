@ECHO OFF

:: cert info to use for signing
SET CERT=2FA35B20356EFEB88F9E9B5F20221693C57100E5
set TSAURL=http://time.certum.pl/
set LIBNAME=Crypture
set LIBURL=https://github.com/NoMoreFood/Crypture

:: setup environment variables based on location of this script
SET BASEDIR=%~dp0.
SET BINDIR=%~dp0..\bin\Release
SET OUTDIR=%~dp0..\..\Binaries
SET VERSION=1.0.1.7

:: cleanup binary directory
DEL /F /S /Q "%BINDIR%\*.*obj"
DEL /F /S /Q "%BINDIR%\*.xml"
DEL /F /S /Q "%BINDIR%\*.pdb"
DEL /F /S /Q "%OUTDIR%\*.msi"

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\10.0.17134.0\x64
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64
SET PATH=%PATH%;%PX86%\WiX Toolset v3.11\bin

:: sign the main executables
signtool sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.exe" 
signtool sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.exe"

:: do the build
PUSHD "%BINDIR%"
candle -arch x86 -dWin64=no -ext WixNetFxExtension -dVersion="%VERSION%" "%BASEDIR%\Crypture.wxs"
light -ext WixUIExtension -ext WixUtilExtension -ext WixNetFxExtension -sval Crypture.wixobj -spdb -o "%OUTDIR%\Crypture-x86-%VERSION%-installer.msi"
DEL /F /S /Q "%BINDIR%\*.*obj"
candle -arch x64 -dWin64=yes -ext WixNetFxExtension -dVersion="%VERSION%" "%BASEDIR%\Crypture.wxs"
light -ext WixUIExtension -ext WixUtilExtension -ext WixNetFxExtension -sval Crypture.wixobj -spdb -o "%OUTDIR%\Crypture-x64-%VERSION%-installer.msi"
DEL /F /S /Q "%BINDIR%\*.*obj"
POPD

:: sign the msi files
signtool sign /sha1 %CERT% /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%OUTDIR%\*.msi"

PAUSE
