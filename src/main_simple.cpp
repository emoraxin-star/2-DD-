#include <Windows.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <json/json.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_opengl3.h"
#include "file_loader.h"

namespace fs = std::filesystem;

// Global variables
HINSTANCE hInstance = NULL;
HWND hwnd = NULL;
HDC hdc = NULL;
HGLRC gl_context = NULL;
LiberTeaBrowser *browser = NULL;

// Forward declarations
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
bool CreateGLContext();
void CleanupGL();

// Basic OpenGL helper functions
PFNGLCREATESHADERPROC glCreateShader = NULL;
PFNGLCREATESHADERPROGRAMVPROC glCreateShaderProgramv = NULL;
PFNGLATTACHSHADERPROC glAttachShader = NULL;
PFNGLLINKPROGRAMPROC glLinkProgram = NULL;
PFNGLUSEPROGRAMPROC glUseProgram = NULL;
PFNGLGETATTRIBLOCATIONPROC glGetAttribLocation = NULL;
PFNGLGETUNIFORMLOCATIONPROC glGetUniformLocation = NULL;
PFNGLSHADERSOURCEPROC glShaderSource = NULL;
PFNGLBINDVERTEXARRAYPROC glBindVertexArray = NULL;
PFNGLGENVERTEXARRAYSPROC glGenVertexArrays = NULL;
PFNGLDELETEVERTEXARRAYSPROC glDeleteVertexArrays = NULL;
PFNGLGENBUFFERSPROC glGenBuffers = NULL;
PFNGLBINDBUFFERPROC glBindBuffer = NULL;
PFNGLBUFFERDATAPROC glBufferData = NULL;
PFNGLDELETEBUFFERSPROC glDeleteBuffers = NULL;

PFNGLCREATEPROGRAMPROC glCreateProgram = NULL;
PFNGLDELETEPROGRAMPROC glDeleteProgram = NULL;
PFNGLGETPROGRAMINFOLOGPROC glGetProgramInfoLog = NULL;
PFNGLGETSHADERINFOLOGPROC glGetShaderInfoLog = NULL;
PFNGLSHADERSOURCEPROC glShaderSource = NULL;
PFNGLVERTEXATTRIBPOINTERPROC glVertexAttribPointer = NULL;
PFNGLENABLEVERTEXATTRIBARRAYPROC glEnableVertexAttribArray = NULL;
PFNGLDISABLEVERTEXATTRIBARRAYPROC glDisableVertexAttribArray = NULL;

// OpenGL shader compilation helper
HGLRC CreateSimpleOpenGLContext()
{
    hdc = GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd = {0};
    pfd.nSize = sizeof(PIXELFORMATDESCRIPTOR);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 24;
    pfd.cDepthBits = 16;
    pfd.iLayerType = PFD_MAIN_PLANE;
    
    int pixel_format = ChoosePixelFormat(hdc, &pfd);
    if (pixel_format == 0)
        return NULL;
    
    HGLRC glrc = wglCreateContext(hdc);
    if (glrc == NULL)
        return NULL;
    
    if (!wglMakeCurrent(hdc, glrc))
    {
        wglDeleteContext(glrc);
        return NULL;
    }
    
    return glrc;
}

// Initialize OpenGL extensions
bool InitOpenGLExtensions()
{
    glCreateShader = (PFNGLCREATESHADERPROC)wglGetProcAddress("glCreateShader");
    glCreateShaderProgramv = (PFNGLCREATESHADERPROGRAMVPROC)wglGetProcAddress("glCreateShaderProgramv");
    glAttachShader = (PFNGLATTACHSHADERPROC)wglGetProcAddress("glAttachShader");
    glLinkProgram = (PFNGLLINKPROGRAMPROC)wglGetProcAddress("glLinkProgram");
    glUseProgram = (PFNGLUSEPROGRAMPROC)wglGetProcAddress("glUseProgram");
    glGetAttribLocation = (PFNGLGETATTRIBLOCATIONPROC)wglGetProcAddress("glGetAttribLocation");
    glGetUniformLocation = (PFNGLGETUNIFORMLOCATIONPROC)wglGetProcAddress("glGetUniformLocation");
    glShaderSource = (PFNGLSHADERSOURCEPROC)wglGetProcAddress("glShaderSource");
    glBindVertexArray = (PFNGLBINDVERTEXARRAYPROC)wglGetProcAddress("glBindVertexArray");
    glGenVertexArrays = (PFNGLGENVERTEXARRAYSPROC)wglGetProcAddress("glGenVertexArrays");
    glDeleteVertexArrays = (PFNGLDELETEVERTEXARRAYPROC)wglGetProcAddress("glDeleteVertexArrays");
    glGenBuffers = (PFNGLGENBUFFERSPROC)wglGetProcAddress("glGenBuffers");
    glBindBuffer = (PFNGLBINDBUFFERPROC)wglGetProcAddress("glBindBuffer");
    glBufferData = (PFNGLBUFFERDATAPROC)wglGetProcAddress("glBufferData");
    glDeleteBuffers = (PFNGLDELETEBUFFERSPROC)wglGetProcAddress("glDeleteBuffers");
    glCreateProgram = (PFNGLCREATEPROGRAMPROC)wglGetProcAddress("glCreateProgram");
    glDeleteProgram = (PFNGLDELETEPROGRAMPROC)wglGetProcAddress("glDeleteProgram");
    glGetProgramInfoLog = (PFNGLGETPROGRAMINFOLOGPROC)wglGetProcAddress("glGetProgramInfoLog");
    glGetShaderInfoLog = (PFNGLGETSHADERINFOLOGPROC)wglGetProcAddress("glGetShaderInfoLog");
    glVertexAttribPointer = (PFNGLVERTEXATTRIBPOINTERPROC)wglGetProcAddress("glVertexAttribPointer");
    glEnableVertexAttribArray = (PFNGLENABLEVERTEXATTRIBARRAYPROC)wglGetProcAddress("glEnableVertexAttribArray");
    glDisableVertexAttribArray = (PFNGLDISABLEVERTEXATTRIBARRAYPROC)wglGetProcAddress("glDisableVertexAttribArray");
    
    // Check if essential functions loaded
    return glCreateShader && glCreateProgram && glBindVertexArray && glGenVertexArrays;
}

void RenderSimpleText(float x, float y, const std::string& text, float scale = 1.0f, ImVec4 color = ImVec4(1, 1, 1, 1))
{
    ImGui::GetWindowDrawList()->AddText(
        ImGui::GetFont(),
        ImGui::GetFontSize() * scale,
        ImVec2(x, y),
        ImGui::ColorConvertFloat4ToU32(color),
        text.c_str(),
        text.c_str() + text.length()
    );
}

void SimpleFileList(const fs::path& directory, fs::path& selected_file)
{
    ImGui::Text("Files in %s:", directory.string().c_str());
    ImGui::Separator();
    
    int count = 0;
    for (const auto& entry : fs::directory_iterator(directory))
    {
        if (entry.is_regular_file() && !entry.path().filename().string().starts_with('.'))
        {
            std::string filename = entry.path().filename().string();
            uintmax_t size = entry.file_size();
            
            std::string display = filename;
            if (size < 1024)
                display += " (" + std::to_string(size) + " B)";
            else if (size < 1024*1024)
                display += " (" + std::to_string(size/1024) + " KB)";
            else
                display += " (" + std::to_string(size/(1024*1024)) + " MB)";
            
            if (ImGui::Selectable(display.c_str(), selected_file == entry.path(), ImGuiSelectableFlags_AllowDoubleClick))
            {
                if (ImGui::IsMouseDoubleClicked(0))
                {
                    selected_file = entry.path();
                    return;
                }
            }
            count++;
        }
    }
    
    if (count == 0)
        ImGui::TextDisabled("(empty)");
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstanceInput,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    hInstance = hInstanceInput;

    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_OWNDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"LiberTeaBrowserClass";
    
    if (!RegisterClassEx(&wc))
    {
        MessageBox(NULL, L"Failed to register window class", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    hwnd = CreateWindowEx(
        0,
        L"LiberTeaBrowserClass",
        L"LiberTea Browser - Minimal",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1024, 720,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd)
    {
        MessageBox(NULL, L"Failed to create window", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Initialize OpenGL
    gl_context = CreateSimpleOpenGLContext();
    if (!gl_context)
    {
        MessageBox(NULL, L"Failed to create OpenGL context", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialize ImGui
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplOpenGL3_Init("#version 410");

    // Create browser instance
    browser = new LiberTeaBrowser("C:/Users/emora/OneDrive/Desktop/2");

    // Initialize data
    browser->LoadFileTreeData();
    browser->LoadPatternStats();

    // Main loop
    MSG msg = {};
    auto last_time = std::chrono::high_resolution_clock::now();

    while (true)
    {
        auto current_time = std::chrono::high_resolution_clock::now();
        auto duration = current_time - last_time;
        last_time = current_time;
        float delta_time = std::chrono::duration<float, std::chrono::seconds::period>(duration).count();

        // Process messages
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                break;
        }

        if (msg.message == WM_QUIT)
            break;

        // Update browser
        browser->Update(delta_time);

        // Start ImGui frame
        ImGui_ImplWin32_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();

        // Render ImGui
        browser->Render();

        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        // Swap buffers
        SwapBuffers(hdc);

        // Small delay to prevent 100% CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    // Cleanup
    delete browser;
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    wglDeleteContext(gl_context);
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);

    return (int) msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    ImGuiIO& io = ImGui::GetIO();

    switch (msg)
    {
        case WM_SIZE:
            io.DisplaySize = ImVec2((float)LOWORD(lparam), (float)HIWORD(lparam));
            break;
        case WM_KEYDOWN:
            io.KeysDown[wparam] = (GetAsyncKeyState(wparam) & 0x8000) != 0;
            break;
        case WM_CHAR:
            if (io.WantCaptureKeyboard)
                return 0;
            io.AddInputCharacter((ImWchar)wparam);
            break;
        case WM_MOUSEWHEEL:
            io.MouseWheel += GET_WHEEL_DELTA_WPARAM(wparam) / WHEEL_DELTA;
            break;
        case WM_MOUSEMOVE:
            io.MousePos = ImVec2((float)LOWORD(lparam), (float)HIWORD(lparam));
            break;
        case WM_LBUTTONDOWN:
            io.MouseDown[0] = true;
            break;
        case WM_LBUTTONUP:
            io.MouseDown[0] = false;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProc(hwnd, msg, wparam, lparam);
}