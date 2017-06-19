@ECHO OFF

:: cert info to use for signing
SET CERT=9CC90E20ABF21CDEF09EE4C467A79FD454140C5A
set TSAURL=http://time.certum.pl/
set LIBNAME=Crypture
set LIBURL=https://github.com/NoMoreFood/Crypture

:: setup environment variables based on location of this script
SET BINDIR=%~dp0..\bin\Release

:: cleanup binary directory
DEL /F /S /Q "%BINDIR%\*.xml"

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\x64
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64

:: sign the main executables
signtool sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.exe" 
signtool sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\*.exe"

:: zip files to output directory
SET ZIPFILE=%~dp0..\Binaries\Crypture.zip
DEL /F /Q "%ZIPFILE%"
POWERSHELL.EXE -NoLogo -NoProfile -Command "& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory('%BINDIR%','%ZIPFILE%'); }"
PAUSE