# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.1.0)
set(toolchainVersion 13_3_Rel1)
set(picotoolVersion 2.1.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico_w CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
include(pico_sdk_import.cmake)

if (PICO_SDK_VERSION_STRING VERSION_LESS "1.4.0")
  message(FATAL_ERROR "Raspberry Pi Pico SDK version 1.4.0 (or later) required. Your version is ${PICO_SDK_VERSION_STRING}")
endif()

project(picow_wlan_setup C CXX ASM)

add_subdirectory(./m24c0x/src)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(picow_wlan_setup_background
        picow_wlan_setup.cpp
        dhcpserver/dhcpserver.c
        dnsserver/dnsserver.c
        )

target_include_directories(picow_wlan_setup_background PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        ${CMAKE_CURRENT_LIST_DIR}/dhcpserver
        ${CMAKE_CURRENT_LIST_DIR}/dnsserver
        )

target_link_libraries(picow_wlan_setup_background
        pico_cyw43_arch_lwip_threadsafe_background
        pico_stdlib
        m24c0x
        )

pico_add_extra_outputs(picow_wlan_setup_background)
pico_enable_stdio_usb(picow_wlan_setup_background 1)
pico_enable_stdio_uart(picow_wlan_setup_background 0)

add_executable(picow_wlan_setup_poll
        picow_wlan_setup.cpp
        dhcpserver/dhcpserver.c
        dnsserver/dnsserver.c
        )
target_include_directories(picow_wlan_setup_poll PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/.. # for our common lwipopts
        ${CMAKE_CURRENT_LIST_DIR}/dhcpserver
        ${CMAKE_CURRENT_LIST_DIR}/dnsserver
        )
target_link_libraries(picow_wlan_setup_poll
        pico_cyw43_arch_lwip_poll
        pico_stdlib
        m24c0x
        )
pico_add_extra_outputs(picow_wlan_setup_poll)
pico_enable_stdio_usb(picow_wlan_setup_poll 1)
pico_enable_stdio_uart(picow_wlan_setup_poll 0)
