@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1

set PICO_SDK_PATH=C:\source\pico-sdk
set PATH=C:\arm-gnu-toolchain\bin;%PATH%

cd /d C:\source\BareMetalWeb\baremetalweb-native\pico

if exist build rmdir /s /q build
mkdir build
cd build

cmake .. -G Ninja -DPICO_TOOLCHAIN_PATH=C:\arm-gnu-toolchain
if errorlevel 1 (
    echo CMAKE CONFIGURE FAILED
    exit /b 1
)

ninja
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

echo.
echo === BUILD SUCCESS ===
dir /b *.uf2 2>nul
echo.
