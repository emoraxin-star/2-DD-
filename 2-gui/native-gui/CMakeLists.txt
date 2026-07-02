cmake_minimum_required(VERSION 3.16)
project(LiberTeaBrowser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MSVC settings
if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc)
    add_link_options(/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup)
endif()

# ImGui
add_subdirectory(imgui)

# Main executable - simple version
add_executable(LiberTeaBrowser
    src/main_simple.cpp
    src/browser.h
    src/file_loader.cpp
    src/file_loader.h
)

target_link_libraries(LiberTeaBrowser PRIVATE imgui)
target_include_directories(LiberTeaBrowser PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR}/imgui)

# Copy data files to build directory
add_custom_command(TARGET LiberTeaBrowser POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/data
        $<TARGET_FILE_DIR:LiberTeaBrowser>/data
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/logs
        $<TARGET_FILE_DIR:LiberTeaBrowser>/logs
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/docs
        $<TARGET_FILE_DIR:LiberTeaBrowser>/docs
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/scripts
        $<TARGET_FILE_DIR:LiberTeaBrowser>/scripts
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/resweep
        $<TARGET_FILE_DIR:LiberTeaBrowser>/resweep
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/build_scripts
        $<TARGET_FILE_DIR:LiberTeaBrowser>/build_scripts
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/README.md
        $<TARGET_FILE_DIR:LiberTeaBrowser>/
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/MASTER_INDEX.txt
        $<TARGET_FILE_DIR:LiberTeaBrowser>/
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/LIBERTEA.DLL
        $<TARGET_FILE_DIR:LiberTeaBrowser>/
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/.text_decompressed.bin
        $<TARGET_FILE_DIR:LiberTeaBrowser>/
)