#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <filesystem>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_opengl3.h"
#include "browser.h"

namespace fs = std::filesystem;

// Forward declarations
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
LRESULT CALLBACK ImGui_ImplWin32_WndProcThunk(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, INT_PTR udata);

// Global variables
HINSTANCE hInstance = NULL;
HGLRC gl_context = NULL;
HWND hwnd = NULL;
HDC hdc = NULL;

// For VS compatibility
const CHAR g_szClassName[] = "LiberTeaBrowserClass";

int APIENTRY wWinMain(_In_ HINSTANCE hInstanceInput,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    // Initialize Winsock
    WSAData wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    hInstance = hInstanceInput;

    // Create main window
    HWND hwnd = CreateWindowEx(
        0,
        g_szClassName,
        L"LiberTea RE Browser",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd)
    {
        DWORD err = GetLastError();
        MessageBox(NULL, L"Failed to create window!", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialize OpenGL
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Initialize ImGui
    ImGui_ImplWin32_Init(hwnd);
    const char* glsl_version = "410";
    gl_context = ImGui_ImplOpenGL3_Init(glsl_version);

    // Create browser instance
    LiberTeaBrowser browser(hwnd, gl_context);

    // Main message loop
    MSG msg = {};
    while (msg.message != WM_QUIT && browser.IsRunning())
    {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else
        {
            browser.RunFrame();
        }
    }

    // Cleanup
    browser.Shutdown();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    wglDeleteContext(wglGetCurrentContext());
    ReleaseDC(hwnd, hdc);
    DestroyWindow(hwnd);

    WSACleanup();

    return (int) msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    ImGuiIO& io = ImGui::GetIO();

    switch (msg)
    {
        case WM_SIZE:
            if (wparam == SIZE_MINIMIZED)
                return 0;
            io.DisplaySize = ImVec2((float)LOWORD(lparam), (float)HIWORD(lparam));
            break;
        case WM_KEYDOWN:
            switch (wparam)
            {
                case VK_F4:
                    if (GetKeyState(VK_MENU) < 0)
                        PostQuitMessage(0);
                    break;
                case VK_CONTROL:
                    if (HIWORD(lparam) & KF_REPEAT)
                        return 0;
                    io.KeysDown[VK_CONTROL] = (LOWORD(lparam) & KF_REPEAT) == 0;
                    break;
                case VK_MENU:
                    if (HIWORD(lparam) & KF_REPEAT)
                        return 0;
                    io.KeysDown[VK_MENU] = (LOWORD(lparam) & KF_REPEAT) == 0;
                    break;
                case 'F':
                    if (GetKeyState(VK_CONTROL) < 0)
                        PostMessage(hwnd, WM_COMMAND, ID_VIEW_SEARCH, 0);
                    break;
                case 'T':
                    if (GetKeyState(VK_CONTROL) < 0)
                        PostMessage(hwnd, WM_COMMAND, ID_VIEW_TOOLS, 0);
                    break;
            }
            break;
        case WM_CHAR:
            if (io.WantCaptureKeyboard)
                return 0;
            break;
        case WM_MOUSEWHEEL:
            io.MouseWheel += GET_WHEEL_DELTA_WPARAM(wparam) / WHEEL_DELTA;
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProc(hwnd, msg, wparam, lparam);
}

LRESULT CALLBACK ImGui_ImplWin32_WndProcThunk(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, INT_PTR udata)
{
    return ImGui_ImplWin32_WndProc(hwnd, msg, wparam, lparam);
}