cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2_w)

# Point to Pico SDK — set PICO_SDK_PATH env or pass -DPICO_SDK_PATH=...
include($ENV{PICO_SDK_PATH}/pico_sdk_init.cmake)

project(baremetalweb_pico C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

# ---- Generate embedded files from wwwroot ----
# Run at configure time so the .c/.h exist before build
execute_process(
    COMMAND ${CMAKE_COMMAND} -E env python3 ${CMAKE_CURRENT_SOURCE_DIR}/gen_embedded.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE GEN_RESULT
)
if(NOT GEN_RESULT EQUAL 0)
    # Try 'python' if 'python3' not found
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env python ${CMAKE_CURRENT_SOURCE_DIR}/gen_embedded.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        RESULT_VARIABLE GEN_RESULT2
    )
    if(NOT GEN_RESULT2 EQUAL 0)
        message(WARNING "Could not run gen_embedded.py — make sure embedded files exist")
    endif()
endif()

add_executable(${PROJECT_NAME}
    bmw_pico_main.c
    bmw_pico_lwip.c
    embedded/bmw_embedded_files.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/embedded
)

target_link_libraries(${PROJECT_NAME}
    pico_stdlib
    pico_cyw43_arch_lwip_poll
    hardware_gpio
)

# WiFi credentials (override with -DBMW_WIFI_SSID=... -DBMW_WIFI_PASS=...)
if(DEFINED BMW_WIFI_SSID)
    target_compile_definitions(${PROJECT_NAME} PRIVATE BMW_WIFI_SSID="${BMW_WIFI_SSID}")
endif()
if(DEFINED BMW_WIFI_PASS)
    target_compile_definitions(${PROJECT_NAME} PRIVATE BMW_WIFI_PASS="${BMW_WIFI_PASS}")
endif()

# USB stdio for debug output
pico_enable_stdio_usb(${PROJECT_NAME} 1)
pico_enable_stdio_uart(${PROJECT_NAME} 0)

# Generate UF2 for BOOTSEL drag-and-drop
pico_add_extra_outputs(${PROJECT_NAME})
