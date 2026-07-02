#pragma once

#include "file_loader.h"
#include <imgui.h>
#include <string>
#include <vector>
#include <filesystem>
#include <memory>

namespace fs = std::filesystem;

enum class TabType {
    FileTree,
    Viewer,
    Strings,
    Patterns,
    HexDump,
    Search
};

struct ViewerState {
    fs::path current_file;
    size_t offset = 0;
    size_t limit = 2000;
    std::string filter;
    std::string encoding = "utf-8";
    TextFileContent content;
};

struct StringsState {
    std::string current_file = "all_strings.txt";
    size_t offset = 0;
    size_t limit = 100;
    std::string filter;
    std::vector<StringEntry> strings;
    size_t total = 0;
};

struct PatternsState {
    std::string module_filter;
    std::string hook_type_filter;
    std::string query;
    size_t offset = 0;
    size_t limit = 50;
    std::vector<PatternEntry> patterns;
    size_t total = 0;
    std::vector<std::string> modules;
    std::vector<std::string> hook_types;
};

struct HexState {
    fs::path current_file;
    uint64_t offset = 0;
    size_t length = 512;
    std::vector<HexLine> lines;
    uintmax_t total_size = 0;
};

struct SearchState {
    std::string query;
    size_t offset = 0;
    size_t limit = 50;
    std::vector<SearchResult> results;
};

class Browser {
public:
    Browser(const fs::path& project_root);
    void Render();
    
private:
    fs::path project_root_;
    TabType current_tab_ = TabType::FileTree;
    
    // Sidebar
    bool show_sidebar_ = true;
    float sidebar_width_ = 300.0f;
    std::string sidebar_filter_;
    
    // File tree data
    std::vector<FileEntry> root_files_;
    std::vector<FileEntry> data_files_;
    std::vector<FileEntry> doc_files_;
    std::vector<FileEntry> log_files_;
    std::vector<FileEntry> script_files_;
    fs::path selected_file_;
    
    // State per tab
    ViewerState viewer_state_;
    StringsState strings_state_;
    PatternsState patterns_state_;
    HexState hex_state_;
    SearchState search_state_;
    
    // UI helpers
    void RenderMenuBar();
    void RenderSidebar();
    void RenderFileTree(const char* label, std::vector<FileEntry>& files, bool& open);
    void RenderViewerTab();
    void RenderStringsTab();
    void RenderPatternsTab();
    void RenderHexTab();
    void RenderSearchTab();
    void RenderStatusBar();
    
    // Actions
    void LoadFile(const fs::path& path);
    void RefreshCurrentTab();
    void LoadPatternStats();
    void LoadStringsList();
    void LoadPatternsList();
    void DoSearch();
};