# ImGui CMakeLists.txt
cmake_minimum_required(VERSION 3.16)

set(IMGUI_SOURCES
    imgui.cpp
    imgui_draw.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    imgui_demo.cpp
)

add_library(imgui STATIC ${IMGUI_SOURCES})
target_include_directories(imgui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(imgui PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

# Backend: Win32 + OpenGL3
set(IMGUI_BACKEND_SOURCES
    backends/imgui_impl_win32.cpp
    backends/imgui_impl_opengl3.cpp
)

add_library(imgui_backend STATIC ${IMGUI_BACKEND_SOURCES})
target_include_directories(imgui_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/backends)
target_link_libraries(imgui_backend PUBLIC imgui)

# Link OpenGL on Windows
if(WIN32)
    target_link_libraries(imgui_backend PUBLIC opengl32 gdi32 user32)
endif()