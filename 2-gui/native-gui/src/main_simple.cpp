#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <ShlObj.h>
#include <shellapi.h>
#include <GL/gl.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cctype>
#include <cstdio>
#include <json.hpp>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_opengl3.h"
#include "file_loader.h"

namespace fs = std::filesystem;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

// ============================================================
// Globals
// ============================================================
HINSTANCE g_hInstance = NULL;
HWND g_hwnd = NULL;
HDC g_hdc = NULL;
HGLRC g_gl_context = NULL;
int g_win_x = 50, g_win_y = 50, g_win_w = 1280, g_win_h = 800;

enum ThemeMode { Theme_Dark, Theme_Light, Theme_Matrix };
ThemeMode g_theme = Theme_Dark;
bool g_theme_menu_open = false;

// Root path & files
fs::path g_root = "C:/Users/emora/OneDrive/Desktop/2";
fs::path g_browse_dir;
std::vector<FileEntry> g_files;

// Sidebar
bool g_sidebar = true;
float g_side_w = 260.0f;

// Background image
bool g_bg_enabled = false;
std::string g_bg_path;
GLuint g_bg_tex = 0;
float g_bg_opacity = 0.25f;
int g_bg_img_w = 0, g_bg_img_h = 0;
ULONG_PTR g_gdi_token = 0;

// Viewer state
fs::path g_opened;
TextFileContent g_txt;
std::vector<HexLine> g_hex;
bool g_is_txt = false;
bool g_force_txt = false;
bool g_force_hex = false;
std::vector<uint8_t> g_raw_bytes;
char g_find_buf[256] = {};

// Search
char g_srch_buf[256] = {};
std::vector<SearchResult> g_srch;

// ============================================================
// Notepad
// ============================================================
static const int NOTEPAD_MAX = 1024 * 1024;
char g_notepad_buf[NOTEPAD_MAX] = {};
std::string g_notepad_path;
bool g_notepad_modified = false;
char g_notepad_find[256] = {};

void NotepadNew() {
    g_notepad_buf[0] = 0;
    g_notepad_path.clear();
    g_notepad_modified = false;
}
bool NotepadLoad(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::string s((std::istreambuf_iterator<char>(f)), {});
    size_t n = (std::min)(s.size(), (size_t)NOTEPAD_MAX - 1);
    memcpy(g_notepad_buf, s.data(), n);
    g_notepad_buf[n] = 0;
    g_notepad_path = path;
    g_notepad_modified = false;
    return true;
}
bool NotepadSave() {
    if (g_notepad_path.empty()) return false;
    std::ofstream f(g_notepad_path, std::ios::binary);
    if (!f) return false;
    f.write(g_notepad_buf, strlen(g_notepad_buf));
    g_notepad_modified = false;
    return true;
}
bool NotepadSaveAs(const std::string& path) {
    g_notepad_path = path;
    return NotepadSave();
}
void NotepadClearModified() { g_notepad_modified = false; }

// ============================================================
// GitHub / Git integration
// ============================================================
std::string RunCmd(const char* cmd) {
    std::string result;
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) return "(failed to run command)";
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    _pclose(pipe);
    return result;
}
bool GitAvailable() {
    std::string r = RunCmd("git --version 2>nul");
    return r.find("git version") != std::string::npos;
}
bool GhAvailable() {
    std::string r = RunCmd("gh --version 2>nul");
    return r.find("gh version") != std::string::npos;
}
std::string Git(const std::string& args, const std::string& dir = "") {
    if (dir.empty())
        return RunCmd(("git " + args + " 2>&1").c_str());
    return RunCmd(("cd /d \"" + dir + "\" && git " + args + " 2>&1").c_str());
}

// GitHub tab state
char g_gh_clone_url[1024] = {};
char g_gh_init_dir[MAX_PATH] = {};
char g_gh_commit_msg[512] = {};
char g_gh_remote_url[1024] = {};
std::string g_gh_repo_dir;
std::string g_gh_output;
std::string g_gh_status;
char g_gh_output_buf[16384] = {};

void GhInitDir() { g_gh_repo_dir = g_root.string(); }
void GhRun(const std::string& args) {
    g_gh_output = Git(args, g_gh_repo_dir);
    strncpy_s(g_gh_output_buf, g_gh_output.c_str(), sizeof(g_gh_output_buf) - 1);
}

// ============================================================
// Font system
// ============================================================
struct FontInfo { std::string name; std::string path; };
std::vector<FontInfo> g_fonts;
int g_font_idx = 0;
float g_font_size = 14.0f;
ImFont* g_font_regular = NULL;
ImFont* g_font_bold = NULL;
ImFont* g_font_mono = NULL;

void ScanFonts() {
    g_fonts.clear();
    const char* windir = getenv("WINDIR");
    if (!windir) return;
    fs::path fontdir = fs::path(windir) / "Fonts";
    
    struct { const char* name; const char* file; } candidates[] = {
        {"Consolas", "consola.ttf"},
        {"Consolas Bold", "consolab.ttf"},
        {"Consolas Italic", "consolai.ttf"},
        {"Courier New", "cour.ttf"},
        {"Courier New Bold", "courbd.ttf"},
        {"Lucida Console", "lucon.ttf"},
        {"Cascadia Code", "CascadiaCode.ttf"},
        {"Cascadia Mono", "CascadiaMono.ttf"},
        {"Fira Code", "FiraCode-Regular.ttf"},
        {"JetBrains Mono", "JetBrainsMono-Regular.ttf"},
        {"Source Code Pro", "SourceCodePro-Regular.ttf"},
        {"Segoe UI", "segoeui.ttf"},
        {"Segoe UI Bold", "segoeuib.ttf"},
        {"Arial", "arial.ttf"},
        {"Microsoft Sans Serif", "micross.ttf"},
    };
    for (auto& c : candidates) {
        fs::path fp = fontdir / c.file;
        if (fs::exists(fp)) {
            g_fonts.push_back({c.name, fp.string()});
        }
    }
    // Always have default
    if (g_fonts.empty()) {
        g_fonts.push_back({"Default", ""});
    }
}

void ReloadFonts(ImFontAtlas* atlas, int idx, float size) {
    atlas->Clear();
    if (idx >= 0 && idx < (int)g_fonts.size() && !g_fonts[idx].path.empty()) {
        g_font_regular = atlas->AddFontFromFileTTF(g_fonts[idx].path.c_str(), size, NULL,
            atlas->GetGlyphRangesCyrillic());
    }
    if (!g_font_regular)
        g_font_regular = atlas->AddFontDefault();
    g_font_bold = g_font_regular;
    g_font_mono = g_font_regular;
    atlas->Build();
}

float g_text_r = 0.8f, g_text_g = 0.8f, g_text_b = 0.8f;

// Font reload deferral (safe between frames)
bool g_font_dirty = false;
int g_font_dirty_idx = 0;
float g_font_dirty_size = 14.0f;

void FontChangeDeferred(int idx, float size) {
    g_font_dirty = true;
    g_font_dirty_idx = idx;
    g_font_dirty_size = size;
}

void ApplyFontChange() {
    if (!g_font_dirty) return;
    g_font_dirty = false;
    auto& io = ImGui::GetIO();
    ReloadFonts(io.Fonts, g_font_dirty_idx, g_font_dirty_size);
    ImGui_ImplOpenGL3_DestroyDeviceObjects();
}

// ============================================================
// Settings persistence
// ============================================================
fs::path ConfigPath() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    fs::path p(buf);
    return p.parent_path() / "config.json";
}

void SaveSettings() {
    nlohmann::json j;
    j["theme"] = (int)g_theme;
    j["font_idx"] = g_font_idx;
    j["font_size"] = g_font_size;
    j["text_r"] = g_text_r; j["text_g"] = g_text_g; j["text_b"] = g_text_b;
    j["win_x"] = g_win_x; j["win_y"] = g_win_y;
    j["win_w"] = g_win_w; j["win_h"] = g_win_h;
    j["sidebar"] = g_sidebar;
    j["side_w"] = g_side_w;
    j["bg_enabled"] = g_bg_enabled;
    j["bg_path"] = g_bg_path;
    j["bg_opacity"] = g_bg_opacity;
    j["root"] = g_root.string();
    j["notepad_path"] = g_notepad_path;
    j["notepad_content"] = std::string(g_notepad_buf);
    std::ofstream f(ConfigPath());
    if (f) f << j.dump(2);
}

void LoadSettings() {
    std::ifstream f(ConfigPath());
    if (!f) return;
    nlohmann::json j;
    try { f >> j; } catch (...) { return; }
    if (j.contains("theme")) g_theme = (ThemeMode)(int)j["theme"];
    if (j.contains("font_idx")) g_font_idx = j["font_idx"];
    if (j.contains("font_size")) g_font_size = j["font_size"];
    if (j.contains("text_r")) g_text_r = j["text_r"];
    if (j.contains("text_g")) g_text_g = j["text_g"];
    if (j.contains("text_b")) g_text_b = j["text_b"];
    if (j.contains("win_x")) g_win_x = j["win_x"];
    if (j.contains("win_y")) g_win_y = j["win_y"];
    if (j.contains("win_w")) g_win_w = j["win_w"];
    if (j.contains("win_h")) g_win_h = j["win_h"];
    if (j.contains("sidebar")) g_sidebar = j["sidebar"];
    if (j.contains("side_w")) g_side_w = j["side_w"];
    if (j.contains("bg_enabled")) g_bg_enabled = j["bg_enabled"];
    if (j.contains("bg_path")) g_bg_path = j["bg_path"].get<std::string>();
    if (j.contains("bg_opacity")) g_bg_opacity = j["bg_opacity"];
    if (j.contains("root")) g_root = j["root"].get<std::string>();
    if (j.contains("notepad_path")) g_notepad_path = j["notepad_path"].get<std::string>();
    if (j.contains("notepad_content")) {
        std::string c = j["notepad_content"].get<std::string>();
        size_t n = (std::min)(c.size(), (size_t)NOTEPAD_MAX - 1);
        memcpy(g_notepad_buf, c.data(), n);
        g_notepad_buf[n] = 0;
    }
}

// ============================================================
// Theme — VS Code Dark / GitHub Light / Matrix
// ============================================================
static ImVec4 hex(float r, float g, float b, float a = 1.0f) {
    return ImVec4(r / 255.0f, g / 255.0f, b / 255.0f, a);
}

void ApplyTheme() {
    auto& s = ImGui::GetStyle();
    s.WindowRounding = 4.0f;   s.ChildRounding = 4.0f;
    s.FrameRounding = 3.0f;    s.PopupRounding = 4.0f;
    s.ScrollbarRounding = 3.0f; s.GrabRounding = 3.0f;
    s.TabRounding = 3.0f;
    s.WindowTitleAlign = ImVec2(0.0f, 0.5f);
    s.WindowPadding = ImVec2(8, 6);
    s.FramePadding = ImVec2(8, 3);
    s.ItemSpacing = ImVec2(6, 4);
    s.ItemInnerSpacing = ImVec2(4, 3);
    s.IndentSpacing = 18.0f;
    s.ScrollbarSize = 12.0f;
    s.GrabMinSize = 8.0f;
    s.WindowBorderSize = 0.0f;
    s.ChildBorderSize = 1.0f;
    s.FrameBorderSize = 0.0f;
    s.PopupBorderSize = 0.0f;
    s.TabBorderSize = 0.0f;

    ImVec4* c = s.Colors;

    if (g_theme == Theme_Matrix) {
        // Matrix: spacy dark grey bg, neon text
        s.WindowRounding = 2.0f;
        s.FrameRounding = 0.0f;
        s.ScrollbarRounding = 0.0f;
        s.TabRounding = 0.0f;
        s.WindowBorderSize = 0.0f;
        s.ChildBorderSize = 0.0f;
        s.FrameBorderSize = 1.0f;

        c[ImGuiCol_Text]              = ImVec4(g_text_r, g_text_g, g_text_b, 1.0f);
        c[ImGuiCol_TextDisabled]       = ImVec4(g_text_r*0.4f, g_text_g*0.4f, g_text_b*0.4f, 1.0f);
        c[ImGuiCol_WindowBg]          = hex(10, 12, 10);
        c[ImGuiCol_ChildBg]           = hex(8, 10, 8);
        c[ImGuiCol_PopupBg]           = hex(12, 15, 12, 235);
        c[ImGuiCol_Border]            = hex(0, 80, 0);
        c[ImGuiCol_BorderShadow]      = hex(0, 0, 0, 0);
        c[ImGuiCol_FrameBg]           = hex(12, 18, 12);
        c[ImGuiCol_FrameBgHovered]    = hex(0, 60, 0);
        c[ImGuiCol_FrameBgActive]     = hex(0, 80, 0);
        c[ImGuiCol_TitleBg]           = hex(8, 12, 8);
        c[ImGuiCol_TitleBgActive]     = hex(10, 20, 10);
        c[ImGuiCol_TitleBgCollapsed]  = hex(10, 12, 10);
        c[ImGuiCol_MenuBarBg]         = hex(8, 10, 8);
        c[ImGuiCol_ScrollbarBg]       = hex(10, 12, 10);
        c[ImGuiCol_ScrollbarGrab]     = hex(0, 80, 0);
        c[ImGuiCol_ScrollbarGrabHovered] = hex(0, 120, 0);
        c[ImGuiCol_ScrollbarGrabActive]  = hex(0, 200, 0);
        c[ImGuiCol_CheckMark]         = hex(0, 255, 65);
        c[ImGuiCol_SliderGrab]        = hex(0, 255, 65);
        c[ImGuiCol_SliderGrabActive]  = hex(0, 255, 130);
        c[ImGuiCol_Button]            = hex(0, 60, 20);
        c[ImGuiCol_ButtonHovered]     = hex(0, 100, 40);
        c[ImGuiCol_ButtonActive]      = hex(0, 150, 60);
        c[ImGuiCol_Header]            = hex(0, 80, 30, 120);
        c[ImGuiCol_HeaderHovered]     = hex(0, 120, 50);
        c[ImGuiCol_HeaderActive]      = hex(0, 160, 60);
        c[ImGuiCol_Separator]         = hex(0, 60, 0);
        c[ImGuiCol_SeparatorHovered]  = hex(0, 255, 65);
        c[ImGuiCol_SeparatorActive]   = hex(0, 255, 130);
        c[ImGuiCol_ResizeGrip]        = hex(0, 60, 0);
        c[ImGuiCol_ResizeGripHovered] = hex(0, 255, 65);
        c[ImGuiCol_ResizeGripActive]  = hex(0, 255, 130);
        c[ImGuiCol_Tab]               = hex(10, 14, 10);
        c[ImGuiCol_TabHovered]        = hex(0, 50, 20);
        c[ImGuiCol_TabSelected]       = hex(10, 20, 10);
        c[ImGuiCol_TabSelectedOverline] = hex(0, 255, 65);
        c[ImGuiCol_TabDimmed]         = hex(8, 12, 8);
        c[ImGuiCol_TabDimmedSelected] = hex(10, 18, 10);
        c[ImGuiCol_TabDimmedSelectedOverline] = hex(0, 60, 20);
        c[ImGuiCol_PlotLines]         = hex(0, 255, 65);
        c[ImGuiCol_PlotHistogram]     = hex(0, 255, 65);
        c[ImGuiCol_TableHeaderBg]     = hex(12, 18, 12);
        c[ImGuiCol_TableBorderStrong] = hex(0, 50, 0);
        c[ImGuiCol_TableBorderLight]  = hex(0, 30, 0);
        c[ImGuiCol_TableRowBg]        = hex(0, 0, 0, 0);
        c[ImGuiCol_TableRowBgAlt]     = hex(0, 255, 0, 10);
        c[ImGuiCol_TextLink]          = hex(0, 255, 200);
        c[ImGuiCol_TextSelectedBg]    = hex(0, 100, 40, 120);
        c[ImGuiCol_DragDropTarget]    = hex(0, 255, 65, 120);
        c[ImGuiCol_NavCursor]         = hex(0, 255, 65);
        c[ImGuiCol_NavWindowingHighlight] = hex(0, 255, 65, 100);
        c[ImGuiCol_NavWindowingDimBg] = hex(0, 0, 0, 80);
        c[ImGuiCol_ModalWindowDimBg]  = hex(0, 0, 0, 100);
    } else if (g_theme == Theme_Dark) {
        // VS Code Dark
        c[ImGuiCol_Text]              = hex(204, 204, 204);
        c[ImGuiCol_TextDisabled]       = hex(110, 110, 110);
        c[ImGuiCol_WindowBg]          = hex(37, 37, 38);
        c[ImGuiCol_ChildBg]           = hex(30, 30, 30);
        c[ImGuiCol_PopupBg]           = hex(45, 45, 48, 235);
        c[ImGuiCol_Border]            = hex(60, 60, 60);
        c[ImGuiCol_BorderShadow]      = hex(0, 0, 0, 0);
        c[ImGuiCol_FrameBg]           = hex(60, 60, 60);
        c[ImGuiCol_FrameBgHovered]    = hex(80, 80, 80);
        c[ImGuiCol_FrameBgActive]     = hex(90, 90, 90);
        c[ImGuiCol_TitleBg]           = hex(45, 45, 45);
        c[ImGuiCol_TitleBgActive]     = hex(55, 55, 55);
        c[ImGuiCol_TitleBgCollapsed]  = hex(37, 37, 38);
        c[ImGuiCol_MenuBarBg]         = hex(51, 51, 51);
        c[ImGuiCol_ScrollbarBg]       = hex(30, 30, 30);
        c[ImGuiCol_ScrollbarGrab]     = hex(72, 72, 72);
        c[ImGuiCol_ScrollbarGrabHovered] = hex(90, 90, 90);
        c[ImGuiCol_ScrollbarGrabActive]  = hex(110, 110, 110);
        c[ImGuiCol_CheckMark]         = hex(0, 122, 204);
        c[ImGuiCol_SliderGrab]        = hex(0, 122, 204);
        c[ImGuiCol_SliderGrabActive]  = hex(0, 150, 230);
        c[ImGuiCol_Button]            = hex(14, 99, 156);
        c[ImGuiCol_ButtonHovered]     = hex(0, 122, 204);
        c[ImGuiCol_ButtonActive]      = hex(0, 90, 160);
        c[ImGuiCol_Header]            = hex(9, 71, 113, 180);
        c[ImGuiCol_HeaderHovered]     = hex(9, 71, 113);
        c[ImGuiCol_HeaderActive]      = hex(14, 99, 156);
        c[ImGuiCol_Separator]         = hex(60, 60, 60);
        c[ImGuiCol_SeparatorHovered]  = hex(0, 122, 204);
        c[ImGuiCol_SeparatorActive]   = hex(0, 150, 230);
        c[ImGuiCol_ResizeGrip]        = hex(60, 60, 60);
        c[ImGuiCol_ResizeGripHovered] = hex(0, 122, 204);
        c[ImGuiCol_ResizeGripActive]  = hex(0, 150, 230);
        c[ImGuiCol_Tab]               = hex(45, 45, 45);
        c[ImGuiCol_TabHovered]        = hex(60, 60, 60);
        c[ImGuiCol_TabSelected]       = hex(30, 30, 30);
        c[ImGuiCol_TabSelectedOverline] = hex(0, 122, 204);
        c[ImGuiCol_TabDimmed]         = hex(37, 37, 38);
        c[ImGuiCol_TabDimmedSelected] = hex(30, 30, 30);
        c[ImGuiCol_TabDimmedSelectedOverline] = hex(60, 60, 60);
        c[ImGuiCol_PlotLines]         = hex(0, 122, 204);
        c[ImGuiCol_PlotHistogram]     = hex(0, 122, 204);
        c[ImGuiCol_TableHeaderBg]     = hex(45, 45, 45);
        c[ImGuiCol_TableBorderStrong] = hex(60, 60, 60);
        c[ImGuiCol_TableBorderLight]  = hex(50, 50, 50);
        c[ImGuiCol_TableRowBg]        = hex(0, 0, 0, 0);
        c[ImGuiCol_TableRowBgAlt]     = hex(255, 255, 255, 10);
        c[ImGuiCol_TextLink]          = hex(0, 122, 204);
        c[ImGuiCol_TextSelectedBg]    = hex(9, 71, 113, 150);
        c[ImGuiCol_DragDropTarget]    = hex(0, 122, 204, 180);
        c[ImGuiCol_NavCursor]         = hex(0, 122, 204);
        c[ImGuiCol_NavWindowingHighlight] = hex(255, 255, 255, 140);
        c[ImGuiCol_NavWindowingDimBg] = hex(0, 0, 0, 50);
        c[ImGuiCol_ModalWindowDimBg]  = hex(0, 0, 0, 100);
    } else {
        // GitHub Light
        c[ImGuiCol_Text]              = hex(36, 41, 47);
        c[ImGuiCol_TextDisabled]       = hex(101, 109, 118);
        c[ImGuiCol_WindowBg]          = hex(255, 255, 255);
        c[ImGuiCol_ChildBg]           = hex(246, 248, 250);
        c[ImGuiCol_PopupBg]           = hex(255, 255, 255, 235);
        c[ImGuiCol_Border]            = hex(208, 215, 222);
        c[ImGuiCol_BorderShadow]      = hex(0, 0, 0, 0);
        c[ImGuiCol_FrameBg]           = hex(235, 237, 240);
        c[ImGuiCol_FrameBgHovered]    = hex(208, 215, 222);
        c[ImGuiCol_FrameBgActive]     = hex(182, 192, 200);
        c[ImGuiCol_TitleBg]           = hex(246, 248, 250);
        c[ImGuiCol_TitleBgActive]     = hex(235, 237, 240);
        c[ImGuiCol_TitleBgCollapsed]  = hex(255, 255, 255);
        c[ImGuiCol_MenuBarBg]         = hex(246, 248, 250);
        c[ImGuiCol_ScrollbarBg]       = hex(255, 255, 255);
        c[ImGuiCol_ScrollbarGrab]     = hex(208, 215, 222);
        c[ImGuiCol_ScrollbarGrabHovered] = hex(182, 192, 200);
        c[ImGuiCol_ScrollbarGrabActive]  = hex(139, 148, 158);
        c[ImGuiCol_CheckMark]         = hex(9, 105, 218);
        c[ImGuiCol_SliderGrab]        = hex(9, 105, 218);
        c[ImGuiCol_SliderGrabActive]  = hex(9, 120, 240);
        c[ImGuiCol_Button]            = hex(9, 105, 218);
        c[ImGuiCol_ButtonHovered]     = hex(8, 130, 230);
        c[ImGuiCol_ButtonActive]      = hex(7, 95, 200);
        c[ImGuiCol_Header]            = hex(9, 105, 218, 50);
        c[ImGuiCol_HeaderHovered]     = hex(9, 105, 218, 80);
        c[ImGuiCol_HeaderActive]      = hex(9, 105, 218, 120);
        c[ImGuiCol_Separator]         = hex(208, 215, 222);
        c[ImGuiCol_SeparatorHovered]  = hex(9, 105, 218);
        c[ImGuiCol_SeparatorActive]   = hex(9, 120, 240);
        c[ImGuiCol_ResizeGrip]        = hex(208, 215, 222);
        c[ImGuiCol_ResizeGripHovered] = hex(9, 105, 218);
        c[ImGuiCol_ResizeGripActive]  = hex(9, 120, 240);
        c[ImGuiCol_Tab]               = hex(246, 248, 250);
        c[ImGuiCol_TabHovered]        = hex(235, 237, 240);
        c[ImGuiCol_TabSelected]       = hex(255, 255, 255);
        c[ImGuiCol_TabSelectedOverline] = hex(9, 105, 218);
        c[ImGuiCol_TabDimmed]         = hex(246, 248, 250);
        c[ImGuiCol_TabDimmedSelected] = hex(255, 255, 255);
        c[ImGuiCol_TabDimmedSelectedOverline] = hex(200, 200, 200);
        c[ImGuiCol_PlotLines]         = hex(9, 105, 218);
        c[ImGuiCol_PlotHistogram]     = hex(9, 105, 218);
        c[ImGuiCol_TableHeaderBg]     = hex(246, 248, 250);
        c[ImGuiCol_TableBorderStrong] = hex(208, 215, 222);
        c[ImGuiCol_TableBorderLight]  = hex(235, 237, 240);
        c[ImGuiCol_TableRowBg]        = hex(0, 0, 0, 0);
        c[ImGuiCol_TableRowBgAlt]     = hex(0, 0, 0, 10);
        c[ImGuiCol_TextLink]          = hex(9, 105, 218);
        c[ImGuiCol_TextSelectedBg]    = hex(9, 105, 218, 60);
        c[ImGuiCol_DragDropTarget]    = hex(9, 105, 218, 120);
        c[ImGuiCol_NavCursor]         = hex(9, 105, 218);
        c[ImGuiCol_NavWindowingHighlight] = hex(36, 41, 47, 140);
        c[ImGuiCol_NavWindowingDimBg] = hex(0, 0, 0, 30);
        c[ImGuiCol_ModalWindowDimBg]  = hex(0, 0, 0, 60);
    }
}

void OpenFile(const fs::path& p) {
    g_opened = p;
    g_force_txt = false;
    g_force_hex = false;
    g_find_buf[0] = 0;

    // Always load raw bytes
    std::ifstream f(p, std::ios::binary);
    if (!f) return;
    g_raw_bytes.assign((std::istreambuf_iterator<char>(f)), {});
    f.close();

    // Auto-detect: check for null bytes to decide text vs binary
    bool has_null = false;
    for (size_t i = 0; i < (std::min)(g_raw_bytes.size(), (size_t)4096); i++) {
        if (g_raw_bytes[i] == 0) { has_null = true; break; }
    }
    g_is_txt = !has_null && g_raw_bytes.size() > 0;

    // Load into viewer formats
    if (g_is_txt) {
        std::string txt((const char*)g_raw_bytes.data(), g_raw_bytes.size());
        g_txt.lines.clear();
        std::istringstream iss(txt);
        std::string line;
        while (std::getline(iss, line)) g_txt.lines.push_back(line);
        g_txt.total_lines = g_txt.lines.size();
        g_txt.file_size = g_raw_bytes.size();
        g_txt.is_binary = false;
        g_hex.clear();
    } else {
        g_hex.clear();
        for (size_t i = 0; i < g_raw_bytes.size(); i += 16) {
            HexLine hl;
            hl.offset = (uint64_t)i;
            size_t chunk = (std::min)((size_t)16, g_raw_bytes.size() - i);
            std::ostringstream h, a;
            for (size_t j = 0; j < chunk; j++) {
                h << std::hex << std::setw(2) << std::setfill('0') << (int)g_raw_bytes[i + j] << " ";
                uint8_t c = g_raw_bytes[i + j];
                a << (char)((c >= 32 && c < 127) ? c : '.');
            }
            hl.hex_bytes = h.str();
            hl.ascii = a.str();
            g_hex.push_back(hl);
        }
        g_txt.lines.clear();
    }
}

void BrowseTo(const fs::path& dir) {
    g_browse_dir = dir;
    g_files = FileLoader::ScanDirectory(dir, "");
}

// ============================================================
// Tab: Browse
// ============================================================
void TabBrowse() {
    // Breadcrumb + controls
    ImGui::TextUnformatted(g_browse_dir.empty() ? g_root.string().c_str() : g_browse_dir.string().c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) BrowseTo(g_browse_dir.empty() ? g_root : g_browse_dir);
    ImGui::SameLine();
    if (ImGui::SmallButton("Set Root")) {
        BROWSEINFOA bi = { 0 };
        bi.lpszTitle = "Select root folder";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
        if (pidl) {
            char folder[MAX_PATH] = {};
            SHGetPathFromIDListA(pidl, folder);
            g_root = folder;
            g_browse_dir.clear();
            BrowseTo(g_root);
            CoTaskMemFree(pidl);
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Root")) { g_browse_dir.clear(); BrowseTo(g_root); }
    ImGui::Separator();

    ImGui::BeginChild("##flist", ImVec2(0, 0));
    // Parent directory entry
    fs::path cur = g_browse_dir.empty() ? g_root : g_browse_dir;
    fs::path parent = cur.parent_path();
    if (!g_browse_dir.empty() && parent != cur) {
        if (ImGui::Selectable("  [..]  (parent)", false, ImGuiSelectableFlags_AllowDoubleClick)) {
            if (ImGui::IsMouseDoubleClicked(0)) BrowseTo(parent);
        }
    }

    for (const auto& e : g_files) {
        ImGui::PushID(&e);
        bool d = e.is_directory;
        std::string icon = d ? "\xf0\x9f\x93\x81 " : "\xf0\x9f\x93\x84 ";
        std::string l = icon + e.relative_path.filename().string();
        if (!d) l += "  " + FileLoader::FormatSize(e.size);
        if (d) ImGui::PushStyleColor(ImGuiCol_Text, hex(86, 156, 214));
        if (ImGui::Selectable(l.c_str(), g_opened == e.path, ImGuiSelectableFlags_AllowDoubleClick)) {
            if (ImGui::IsMouseDoubleClicked(0)) {
                if (d) BrowseTo(e.path);
                else OpenFile(e.path);
            }
        }
        if (d) ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(e.path.string().c_str());
            if (!d) ImGui::Text("Size: %s", FileLoader::FormatSize(e.size).c_str());
            ImGui::EndTooltip();
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
}

// ============================================================
// Tab: Viewer
// ============================================================
void TabViewer() {
    if (g_opened.empty()) {
        ImGui::TextDisabled("Double-click a file to open it.");
        return;
    }

    // Header bar: filename + size + mode toggles
    ImGui::BeginChild("##vhead", ImVec2(0, ImGui::GetFontSize() + 16), ImGuiChildFlags_Border);
    ImGui::TextUnformatted(g_opened.filename().string().c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("  %s", g_opened.string().c_str());
    ImGui::SameLine(ImGui::GetWindowWidth() - 320);

    // Mode buttons
    ImGui::TextDisabled("Mode:");
    ImGui::SameLine();
    if (ImGui::SmallButton("Auto")) { g_force_txt = false; g_force_hex = false; }
    ImGui::SameLine();
    if (ImGui::SmallButton("Text")) { g_force_txt = true; g_force_hex = false; }
    ImGui::SameLine();
    if (ImGui::SmallButton("Hex")) { g_force_txt = false; g_force_hex = true; }

    // File info line
    ImGui::TextDisabled("%zu bytes  %s",
        g_raw_bytes.size(),
        (g_is_txt || g_force_txt) && !g_force_hex ? "text" : "binary");
    ImGui::EndChild();

    bool show_hex = g_force_hex || (!g_force_txt && !g_is_txt);

    if (show_hex) {
        // HEX MODE: show hex dump for any file
        if (g_hex.empty() && !g_raw_bytes.empty()) {
            for (size_t i = 0; i < g_raw_bytes.size(); i += 16) {
                HexLine hl;
                hl.offset = (uint64_t)i;
                size_t chunk = (std::min)((size_t)16, g_raw_bytes.size() - i);
                std::ostringstream h, a;
                for (size_t j = 0; j < chunk; j++) {
                    h << std::hex << std::setw(2) << std::setfill('0') << (int)g_raw_bytes[i + j] << " ";
                    uint8_t c = g_raw_bytes[i + j];
                    a << (char)((c >= 32 && c < 127) ? c : '.');
                }
                hl.hex_bytes = h.str();
                hl.ascii = a.str();
                g_hex.push_back(hl);
            }
        }
        ImGui::BeginChild("##vh", ImVec2(0, 0));
        ImGui::TextUnformatted("  Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F    ASCII");
        ImGui::Separator();
        for (auto& hl : g_hex) {
            std::string hb = hl.hex_bytes;
            if (hb.size() > 24) hb.insert(24, " ");
            ImGui::Text("  %08llX    %s   %s", (unsigned long long)hl.offset, hb.c_str(), hl.ascii.c_str());
        }
        ImGui::EndChild();
    } else {
        // TEXT MODE: show lines, with non-printable chars cleaned
        ImGui::InputTextWithHint("##find", "Search in file...", g_find_buf, sizeof(g_find_buf));
        ImGui::Separator();
        ImGui::BeginChild("##vt", ImVec2(0, 0));
        std::string f(g_find_buf);
        std::transform(f.begin(), f.end(), f.begin(),
            [](unsigned char c) { return (unsigned char)std::tolower(c); });
        ImGuiListClipper cl;
        cl.Begin((int)g_txt.lines.size());
        while (cl.Step()) {
            for (int i = cl.DisplayStart; i < cl.DisplayEnd; i++) {
                // Clean line for display: replace non-printables with dots
                std::string clean = g_txt.lines[i];
                for (auto& c : clean)
                    if ((unsigned char)c < 32 && c != '\t') c = '.';
                bool hl = false;
                if (!f.empty()) {
                    std::string lc = clean;
                    std::transform(lc.begin(), lc.end(), lc.begin(),
                        [](unsigned char c) { return (unsigned char)std::tolower(c); });
                    hl = lc.find(f) != std::string::npos;
                }
                if (hl) ImGui::PushStyleColor(ImGuiCol_Text, hex(220, 200, 80));
                ImGui::Text("%6llu  %s", (unsigned long long)(i + 1), clean.c_str());
                if (hl) ImGui::PopStyleColor();
            }
        }
        ImGui::EndChild();
    }
}

// ============================================================
// Tab: Hex
// ============================================================
void TabHex() {
    ImGui::BeginChild("##hhead", ImVec2(0, ImGui::GetFontSize() + 12), ImGuiChildFlags_Border);
    if (!g_opened.empty()) {
        ImGui::TextUnformatted(g_opened.filename().string().c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Reload")) g_hex = FileLoader::LoadHexDump(g_opened, 0, 4096);
        ImGui::SameLine();
        if (ImGui::SmallButton("Load more")) {
            auto more = FileLoader::LoadHexDump(g_opened, g_hex.size() * 16, 4096);
            g_hex.insert(g_hex.end(), more.begin(), more.end());
        }
    } else {
        ImGui::TextDisabled("No file opened");
    }
    ImGui::EndChild();

    ImGui::BeginChild("##hmain", ImVec2(0, 0));
    if (!g_hex.empty()) {
        ImGui::Text("  Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F    ASCII");
        ImGui::Separator();
        ImGuiListClipper cl;
        cl.Begin((int)g_hex.size());
        while (cl.Step()) {
            for (int i = cl.DisplayStart; i < cl.DisplayEnd; i++) {
                auto& h = g_hex[i];
                std::string hb = h.hex_bytes;
                if (hb.size() > 24) hb.insert(24, " ");
                ImGui::Text("  %08llX    %s   %s",
                    (unsigned long long)h.offset, hb.c_str(), h.ascii.c_str());
            }
        }
    }
    ImGui::EndChild();
}

// ============================================================
// Tab: Search
// ============================================================
void TabSearch() {
    ImGui::InputTextWithHint("##q", "Search across all files...", g_srch_buf, sizeof(g_srch_buf));
    ImGui::SameLine();
    if (ImGui::Button("Search")) {
        std::string q(g_srch_buf);
        if (!q.empty()) g_srch = FileLoader::SearchFiles(g_root, q, 200, 0);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) { g_srch_buf[0] = 0; g_srch.clear(); }
    ImGui::TextDisabled("%zu results", g_srch.size());
    ImGui::Separator();
    ImGui::BeginChild("##sr", ImVec2(0, 0));
    for (const auto& r : g_srch) {
        ImGui::PushID(&r);
        bool click = ImGui::Selectable(r.file.filename().string().c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
        if (ImGui::IsItemHovered()) {
            ImGui::BeginTooltip();
            ImGui::Text("File: %s", r.file.string().c_str());
            ImGui::Text("Line: %llu", (unsigned long long)r.line_num);
            ImGui::Separator();
            ImGui::TextWrapped("%s", r.content.c_str());
            ImGui::EndTooltip();
        }
        if (click && ImGui::IsMouseDoubleClicked(0)) {
            fs::path fp = g_root / r.file;
            if (fs::exists(fp)) OpenFile(fp);
        }
        ImGui::TextDisabled("  %s:%llu", r.file.string().c_str(), (unsigned long long)r.line_num);
        ImGui::TextWrapped("  %s", r.content.c_str());
        ImGui::Separator();
        ImGui::PopID();
    }
    ImGui::EndChild();
}

// ============================================================
// Tab: Notepad (Code Editor)
// ============================================================
void TabNotepad() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("New")) NotepadNew();
            if (ImGui::MenuItem("Open...")) {
                OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
                char file[MAX_PATH] = {};
                ofn.lpstrFilter = "All Files\0*.*\0Text\0*.txt\0Code\0*.cpp;*.h;*.py;*.js;*.html;*.css\0";
                ofn.Flags = OFN_FILEMUSTEXIST;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                if (GetOpenFileNameA(&ofn)) NotepadLoad(file);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Save", "Ctrl+S", false, !g_notepad_path.empty())) NotepadSave();
            if (ImGui::MenuItem("Save As...")) {
                OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
                char file[MAX_PATH] = {};
                ofn.lpstrFilter = "All Files\0*.*\0Text\0*.txt\0";
                ofn.Flags = OFN_OVERWRITEPROMPT;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrDefExt = "txt";
                if (GetSaveFileNameA(&ofn)) NotepadSaveAs(file);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Clear")) { g_notepad_buf[0] = 0; g_notepad_modified = true; }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    ImGui::TextUnformatted(g_notepad_path.empty() ? "untitled" : g_notepad_path.c_str());
    if (g_notepad_modified) { ImGui::SameLine(); ImGui::TextColored(hex(200, 200, 80), " *modified*"); }
    ImGui::Separator();

    // Use big font if available
    if (g_font_regular) ImGui::PushFont(g_font_regular);
    ImGui::InputTextMultiline("##np", g_notepad_buf, NOTEPAD_MAX,
        ImVec2(-FLT_MIN, -FLT_MIN),
        ImGuiInputTextFlags_AllowTabInput);
    if (g_font_regular) ImGui::PopFont();

    // Detect content changes
    static size_t prev_len = 0;
    size_t cur_len = strlen(g_notepad_buf);
    if (cur_len != prev_len) { g_notepad_modified = true; prev_len = cur_len; }
}

// ============================================================
// Tab: GitHub
// ============================================================
void TabGitHub() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Help")) {
            ImGui::TextDisabled("Git: %s", GitAvailable() ? "OK" : "NOT FOUND");
            ImGui::TextDisabled("GitHub CLI: %s", GhAvailable() ? "OK" : "NOT FOUND");
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    // Repository path
    ImGui::Text("Repo Dir:");
    ImGui::SameLine();
    char repo_buf[MAX_PATH] = {};
    strncpy_s(repo_buf, g_gh_repo_dir.c_str(), sizeof(repo_buf) - 1);
    if (ImGui::InputText("##repodir", repo_buf, sizeof(repo_buf))) {
        g_gh_repo_dir = repo_buf;
    }
    ImGui::SameLine();
    if (ImGui::Button("Browse")) {
        BROWSEINFOA bi = { 0 };
        bi.lpszTitle = "Select repo folder";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
        if (pidl) {
            char folder[MAX_PATH] = {};
            SHGetPathFromIDListA(pidl, folder);
            g_gh_repo_dir = folder;
            CoTaskMemFree(pidl);
        }
    }

    ImGui::Separator();

    // Row 1: Clone + Init
    if (ImGui::CollapsingHeader("Clone / Init", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputTextWithHint("##clone", "GitHub URL to clone...", g_gh_clone_url, sizeof(g_gh_clone_url));
        ImGui::SameLine();
        if (ImGui::Button("Clone") && strlen(g_gh_clone_url) > 0) {
            GhRun(std::string("clone \"") + g_gh_clone_url + "\"");
            g_gh_clone_url[0] = 0;
        }
        ImGui::SameLine();
        if (ImGui::Button("Init")) {
            if (!fs::exists(g_gh_repo_dir)) fs::create_directories(g_gh_repo_dir);
            GhRun("init");
            GhRun("branch -M main");
        }
        ImGui::SameLine();
        if (ImGui::Button("Status")) { GhRun("status"); }
    }

    // Row 2: Add + Commit + Remote
    if (ImGui::CollapsingHeader("Commit / Remote", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::InputTextWithHint("##msg", "Commit message...", g_gh_commit_msg, sizeof(g_gh_commit_msg))) {}
        ImGui::SameLine();
        if (ImGui::Button("Stage All") && !g_gh_repo_dir.empty()) { GhRun("add -A"); }
        ImGui::SameLine();
        if (ImGui::Button("Commit") && strlen(g_gh_commit_msg) > 0) {
            GhRun(std::string("commit -m \"") + g_gh_commit_msg + "\"");
        }
        ImGui::InputTextWithHint("##remote", "Remote URL...", g_gh_remote_url, sizeof(g_gh_remote_url));
        ImGui::SameLine();
        if (ImGui::Button("Set Remote") && strlen(g_gh_remote_url) > 0) {
            GhRun(std::string("remote add origin \"") + g_gh_remote_url + "\"");
        }
    }

    // Row 3: Push + Pull + Fork
    if (ImGui::CollapsingHeader("Push / Pull / Fork", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Button("Push")) { GhRun("push -u origin main"); }
        ImGui::SameLine();
        if (ImGui::Button("Pull")) { GhRun("pull"); }
        ImGui::SameLine();
        if (ImGui::Button("Log")) { GhRun("log --oneline -10"); }
        ImGui::SameLine();
        if (GhAvailable()) {
            if (ImGui::Button("Fork (gh)")) { GhRun("gh repo fork"); }
        } else {
            ImGui::TextDisabled("Fork requires GitHub CLI (gh)");
        }
    }

    // Row 4: Quick actions
    if (ImGui::CollapsingHeader("Quick Actions", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Button("Init + Add + Commit \"initial\"")) {
            if (!fs::exists(g_gh_repo_dir)) fs::create_directories(g_gh_repo_dir);
            GhRun("init");
            GhRun("branch -M main");
            GhRun("add -A");
            GhRun("commit -m \"initial\"");
        }
        ImGui::SameLine();
        if (ImGui::Button("Init + Clone fallback")) {
            if (!fs::exists(g_gh_repo_dir)) fs::create_directories(g_gh_repo_dir);
            GhRun("init");
        }
        ImGui::SameLine();
        if (ImGui::Button("Open in Explorer")) {
            if (!g_gh_repo_dir.empty()) {
                ShellExecuteA(NULL, "open", g_gh_repo_dir.c_str(), NULL, NULL, SW_SHOWNORMAL);
            }
        }
    }

    ImGui::Separator();
    ImGui::Text("Output:");
    ImGui::BeginChild("##ghout", ImVec2(0, 0), ImGuiChildFlags_Border);
    ImGui::TextWrapped("%s", g_gh_output_buf);
    ImGui::EndChild();
}

// ============================================================
// Settings / Theme Popup
// ============================================================
bool g_show_settings = false;

void ShowSettingsPopup() {
    if (g_show_settings) {
        ImGui::OpenPopup("Settings");
        g_show_settings = false;
    }
    if (ImGui::BeginPopupModal("Settings", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        // Theme
        ImGui::Text("Theme");
        const char* themes[] = { "VS Code Dark", "GitHub Light", "Matrix Neon" };
        int t = (int)g_theme;
        if (ImGui::Combo("##theme", &t, themes, 3)) {
            g_theme = (ThemeMode)t;
            ApplyTheme();
        }

        // Font
        ImGui::Separator();
        ImGui::Text("Font");
        if (ImGui::Combo("##font", &g_font_idx,
            [](void* data, int idx, const char** out) {
                auto* v = (std::vector<FontInfo>*)data;
                if (idx < 0 || idx >= (int)v->size()) return false;
                *out = (*v)[idx].name.c_str();
                return true;
            }, (void*)&g_fonts, (int)g_fonts.size())) {
            FontChangeDeferred(g_font_idx, g_font_size);
        }
        ImGui::SliderFloat("Size", &g_font_size, 10.0f, 24.0f, "%.0f");
        if (ImGui::Button("Apply Font")) {
            FontChangeDeferred(g_font_idx, g_font_size);
        }

        // Text color (only for Matrix mode)
        if (g_theme == Theme_Matrix) {
            ImGui::Separator();
            ImGui::Text("Neon Text Color");
            float col[3] = { g_text_r, g_text_g, g_text_b };
            if (ImGui::ColorEdit3("##textcol", col)) {
                g_text_r = col[0]; g_text_g = col[1]; g_text_b = col[2];
                ApplyTheme();
            }
        }

        // Forward declarations for bg functions defined later
        extern bool LoadBgImage(const std::string&);
        extern void FreeBgTex();

        // Background image
        ImGui::Separator();
        extern bool LoadBgImage(const std::string&);
        extern void FreeBgTex();

        ImGui::Text("Background Image");
        ImGui::Checkbox("Enable", &g_bg_enabled);
        if (ImGui::Button("Choose Image...")) {
            OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
            char file[MAX_PATH] = {};
            ofn.lpstrFilter = "Images\0*.png;*.jpg;*.jpeg;*.bmp;*.gif\0All Files\0*.*\0";
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            ofn.lpstrFile = file;
            ofn.nMaxFile = MAX_PATH;
            if (GetOpenFileNameA(&ofn) && LoadBgImage(file)) {
                g_bg_enabled = true;
            }
        }
        if (!g_bg_path.empty()) {
            ImGui::TextUnformatted(g_bg_path.c_str());
            ImGui::Text("%d x %d", g_bg_img_w, g_bg_img_h);
            if (ImGui::Button("Clear")) {
                g_bg_enabled = false;
                g_bg_path.clear();
                FreeBgTex();
            }
        }
        ImGui::SliderFloat("Opacity", &g_bg_opacity, 0.05f, 1.0f, "%.2f");

        ImGui::Separator();
        if (ImGui::Button("Save Config")) {
            SaveSettings();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

// ============================================================
// Background image
// ============================================================
void FreeBgTex() {
    if (g_bg_tex) { glDeleteTextures(1, &g_bg_tex); g_bg_tex = 0; }
}

bool LoadBgImage(const std::string& path) {
    FreeBgTex();
    if (!fs::exists(path)) return false;
    g_bg_path = path;

    Bitmap bmp(std::wstring(path.begin(), path.end()).c_str());
    if (bmp.GetLastStatus() != Ok) return false;
    g_bg_img_w = bmp.GetWidth();
    g_bg_img_h = bmp.GetHeight();
    if (g_bg_img_w < 1 || g_bg_img_h < 1) return false;

    Rect r(0, 0, g_bg_img_w, g_bg_img_h);
    BitmapData data;
    if (bmp.LockBits(&r, ImageLockModeRead, PixelFormat32bppARGB, &data) != Ok)
        return false;

    // BGRA -> RGBA flip for OpenGL
    std::vector<uint32_t> pixels(g_bg_img_w * g_bg_img_h);
    const uint32_t* src = (const uint32_t*)data.Scan0;
    for (int y = 0; y < g_bg_img_h; y++) {
        for (int x = 0; x < g_bg_img_w; x++) {
            uint32_t c = src[y * (data.Stride / 4) + x];
            uint8_t b = (c >> 0) & 0xFF, g = (c >> 8) & 0xFF;
            uint8_t r2 = (c >> 16) & 0xFF, a = (c >> 24) & 0xFF;
            pixels[y * g_bg_img_w + x] = (a << 24) | (r2 << 16) | (g << 8) | b;
        }
    }
    bmp.UnlockBits(&data);

    glGenTextures(1, &g_bg_tex);
    glBindTexture(GL_TEXTURE_2D, g_bg_tex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, g_bg_img_w, g_bg_img_h, 0,
                 GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP);
    glBindTexture(GL_TEXTURE_2D, 0);
    return true;
}

void RenderBg(int win_w, int win_h) {
    if (!g_bg_enabled || !g_bg_tex) return;
    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadIdentity();
    glOrtho(0, win_w, win_h, 0, -1, 1);
    glMatrixMode(GL_MODELVIEW);
    glPushMatrix();
    glLoadIdentity();

    glEnable(GL_TEXTURE_2D);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glBindTexture(GL_TEXTURE_2D, g_bg_tex);

    // Scale to fill window while maintaining aspect ratio
    float img_aspect = (float)g_bg_img_w / g_bg_img_h;
    float win_aspect = (float)win_w / win_h;
    float u, v;
    if (img_aspect > win_aspect) {
        u = 1.0f;
        v = win_aspect / img_aspect;
    } else {
        u = img_aspect / win_aspect;
        v = 1.0f;
    }
    float cx = (1.0f - u) / 2.0f, cy = (1.0f - v) / 2.0f;

    glColor4f(1, 1, 1, g_bg_opacity);
    glBegin(GL_QUADS);
    glTexCoord2f(cx, cy + v); glVertex2i(0, 0);
    glTexCoord2f(cx + u, cy + v); glVertex2i(win_w, 0);
    glTexCoord2f(cx + u, cy); glVertex2i(win_w, win_h);
    glTexCoord2f(cx, cy); glVertex2i(0, win_h);
    glEnd();

    glBindTexture(GL_TEXTURE_2D, 0);
    glDisable(GL_BLEND);
    glDisable(GL_TEXTURE_2D);

    glMatrixMode(GL_PROJECTION);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);
    glPopMatrix();
}

// ============================================================
// Sidebar
// ============================================================
void RenderSidebar(float height) {
    if (!g_sidebar) return;
    ImGui::BeginChild("##side", ImVec2(g_side_w, height), ImGuiChildFlags_Border | ImGuiChildFlags_ResizeX);
    ImGui::TextUnformatted("Explorer");
    ImGui::Separator();

    fs::path cur = g_browse_dir.empty() ? g_root : g_browse_dir;
    // Up button
    ImGui::BeginDisabled(g_browse_dir.empty());
    if (ImGui::SmallButton(".. Up")) {
        fs::path p = cur.parent_path();
        if (p != cur) BrowseTo(p);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::SmallButton("Root")) { g_browse_dir.clear(); BrowseTo(g_root); }
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh")) BrowseTo(cur);

    ImGui::BeginChild("##sidelist", ImVec2(0, 0));
    // Parent entry
    fs::path parent = cur.parent_path();
    if (!g_browse_dir.empty() && parent != cur) {
        if (ImGui::Selectable("  [..]", false, ImGuiSelectableFlags_AllowDoubleClick)) {
            if (ImGui::IsMouseDoubleClicked(0)) BrowseTo(parent);
        }
    }
    for (const auto& e : g_files) {
        ImGui::PushID(&e);
        bool d = e.is_directory;
        std::string l = e.relative_path.filename().string();
        if (!d) l += "  " + FileLoader::FormatSize(e.size);
        bool sel = (g_opened == e.path);
        if (d) ImGui::PushStyleColor(ImGuiCol_Text, hex(86, 156, 214));
        if (ImGui::Selectable(l.c_str(), sel, ImGuiSelectableFlags_AllowDoubleClick)) {
            if (ImGui::IsMouseDoubleClicked(0)) {
                if (d) BrowseTo(e.path);
                else OpenFile(e.path);
            }
        }
        if (d) ImGui::PopStyleColor();
        ImGui::PopID();
    }
    ImGui::EndChild();

    // Track resize
    g_side_w = ImGui::GetWindowWidth();
    ImGui::EndChild();
    ImGui::SameLine();
}

// ============================================================
// WinMain
// ============================================================
int APIENTRY wWinMain(_In_ HINSTANCE hi,
                      _In_opt_ HINSTANCE,
                      _In_ LPWSTR,
                      _In_ int show)
{
    g_hInstance = hi;
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW), CS_OWNDC, WndProc, 0, 0, hi,
                        NULL, NULL, NULL, NULL, L"LiberTeaBrowserClass", NULL };
    if (!RegisterClassExW(&wc)) return 1;

    // Load settings before creating window (for position/size)
    LoadSettings();
    ScanFonts();

    g_hwnd = CreateWindowExW(0, L"LiberTeaBrowserClass", L"LiberTea Browser",
        WS_OVERLAPPEDWINDOW,
        g_win_x > 0 ? g_win_x : CW_USEDEFAULT,
        g_win_y > 0 ? g_win_y : CW_USEDEFAULT,
        g_win_w, g_win_h, NULL, NULL, hi, NULL);
    if (!g_hwnd) return 1;
    ShowWindow(g_hwnd, show);
    UpdateWindow(g_hwnd);

    g_hdc = GetDC(g_hwnd);
    PIXELFORMATDESCRIPTOR pfd = { sizeof(PIXELFORMATDESCRIPTOR), 1,
        PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER,
        PFD_TYPE_RGBA, 24, 0,0,0,0,0,0,0,0,0,0,0,0,0, 16,0,0,
        PFD_MAIN_PLANE,0,0,0,0 };
    int pf = ChoosePixelFormat(g_hdc, &pfd);
    if (!pf) return 1;
    SetPixelFormat(g_hdc, pf, &pfd);
    g_gl_context = wglCreateContext(g_hdc);
    if (!g_gl_context) return 1;
    wglMakeCurrent(g_hdc, g_gl_context);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = NULL;

    // Load font
    ReloadFonts(io.Fonts, g_font_idx, g_font_size);

    // Init GDI+ for background image loading
    GdiplusStartupInput gdi_input;
    GdiplusStartup(&g_gdi_token, &gdi_input, NULL);

    // Load saved background image (needs GL context active)
    if (!g_bg_path.empty() && fs::exists(g_bg_path))
        LoadBgImage(g_bg_path);

    ApplyTheme();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplOpenGL3_Init("#version 410");

    g_files = FileLoader::ScanDirectory(g_root);
    // If notepad had a path, try to load it
    if (!g_notepad_path.empty() && fs::exists(g_notepad_path)) {
        NotepadLoad(g_notepad_path);
    }

    MSG msg = {};
    while (true) {
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) break;
        }
        if (msg.message == WM_QUIT) break;

        RECT rc; GetClientRect(g_hwnd, &rc);
        int fb_w = rc.right, fb_h = rc.bottom;
        g_win_w = fb_w; g_win_h = fb_h;
        io.DisplaySize = ImVec2((float)fb_w, (float)fb_h);

        ImGui_ImplWin32_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();

        // Menu bar
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("Refresh", "F5"))
                    g_files = FileLoader::ScanDirectory(g_root);
                ImGui::Separator();
                if (ImGui::MenuItem("Settings")) g_show_settings = true;
                if (ImGui::MenuItem("Save Config")) SaveSettings();
                ImGui::Separator();
                if (ImGui::MenuItem("Exit", "Alt+F4")) PostQuitMessage(0);
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("View")) {
                if (ImGui::MenuItem("Sidebar", "Ctrl+B", &g_sidebar)) {}
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Theme")) {
                bool d = (g_theme == Theme_Dark);
                bool l = (g_theme == Theme_Light);
                bool m = (g_theme == Theme_Matrix);
                if (ImGui::MenuItem("VS Code Dark", NULL, &d)) { g_theme = Theme_Dark; ApplyTheme(); }
                if (ImGui::MenuItem("GitHub Light", NULL, &l)) { g_theme = Theme_Light; ApplyTheme(); }
                if (ImGui::MenuItem("Matrix Neon", NULL, &m)) { g_theme = Theme_Matrix; ApplyTheme(); }
                ImGui::EndMenu();
            }
            ImGui::EndMainMenuBar();
        }

        float menuh = ImGui::GetFrameHeight();
        float statush = 22.0f;

        // Settings popup
        ShowSettingsPopup();

        float content_h = (float)fb_h - menuh - statush;

        // Sidebar (left panel)
        RenderSidebar(content_h);
        float side_offset = g_sidebar ? g_side_w + 4.0f : 0.0f;

        // Main content with tabs
        ImGui::SetNextWindowPos(ImVec2(side_offset, menuh));
        ImGui::SetNextWindowSize(ImVec2((float)fb_w - side_offset, content_h));
        ImGui::Begin("##main", NULL,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        if (ImGui::BeginTabBar("##tabs", ImGuiTabBarFlags_NoCloseWithMiddleMouseButton)) {
            if (ImGui::BeginTabItem("Browse", NULL, ImGuiTabItemFlags_None)) { TabBrowse(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Viewer", NULL, ImGuiTabItemFlags_None)) { TabViewer(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Hex", NULL, ImGuiTabItemFlags_None)) { TabHex(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Search", NULL, ImGuiTabItemFlags_None)) { TabSearch(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("Notepad", NULL, ImGuiTabItemFlags_None)) { TabNotepad(); ImGui::EndTabItem(); }
            if (ImGui::BeginTabItem("GitHub", NULL, ImGuiTabItemFlags_None)) { TabGitHub(); ImGui::EndTabItem(); }
            ImGui::EndTabBar();
        }
        ImGui::End();

        // Status bar
        ImGui::SetNextWindowPos(ImVec2(0, (float)fb_h - statush));
        ImGui::SetNextWindowSize(ImVec2((float)fb_w, statush));
        ImGui::Begin("##status", NULL,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse);
        std::string st;
        if (!g_opened.empty())
            st = g_opened.filename().string() + "  |  " + g_opened.string();
        else
            st = std::to_string(g_files.size()) + " entries  |  " + g_root.string();
        ImGui::TextDisabled("%s", st.c_str());
        ImGui::SameLine((float)fb_w - 160);
        const char* theme_names[] = { "Dark", "Light", "Matrix" };
        ImGui::TextDisabled("%s  |  %s  %.0fpx",
            theme_names[(int)g_theme],
            g_font_idx < (int)g_fonts.size() ? g_fonts[g_font_idx].name.c_str() : "?",
            g_font_size);
        ImGui::End();

        // Render
        ImGui::Render();
        if (g_theme == Theme_Matrix) glClearColor(0.035f, 0.045f, 0.035f, 1.0f);
        else if (g_theme == Theme_Dark) glClearColor(0.118f, 0.118f, 0.118f, 1.0f);
        else glClearColor(0.965f, 0.973f, 0.980f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        RenderBg(fb_w, fb_h);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SwapBuffers(g_hdc);

        // Font reload deferred to between frames (safe)
        ApplyFontChange();

        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    // Save settings on exit
    SaveSettings();
    FreeBgTex();
    if (g_gdi_token) GdiplusShutdown(g_gdi_token);

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(g_gl_context);
    ReleaseDC(g_hwnd, g_hdc);
    DestroyWindow(g_hwnd);
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, w, l)) return true;
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    if (msg == WM_GETMINMAXINFO) {
        auto* mmi = (MINMAXINFO*)l;
        mmi->ptMinTrackSize.x = 640;
        mmi->ptMinTrackSize.y = 400;
        return 0;
    }
    return DefWindowProc(hwnd, msg, w, l);
}
