cmake_minimum_required(VERSION 3.16)
project(LiberTeaBrowser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MSVC settings
if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc)
    add_link_options(/SUBSYSTEM:WINDOWS)
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

target_link_libraries(LiberTeaBrowser PRIVATE imgui imgui_backend)
target_include_directories(LiberTeaBrowser PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR}/imgui ${CMAKE_CURRENT_SOURCE_DIR}/deps)
