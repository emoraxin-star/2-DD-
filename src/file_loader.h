#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace fs = std::filesystem;

struct FileEntry {
    fs::path path;
    fs::path relative_path;
    bool is_directory;
    uintmax_t size;
    std::time_t modified;
};

struct TextFileContent {
    std::vector<std::string> lines;
    size_t total_lines = 0;
    size_t file_size = 0;
    bool is_binary = false;
};

struct StringEntry {
    size_t line_num;
    std::string content;
};

struct PatternEntry {
    size_t offset;
    std::string signature;
    std::string name;
    std::string module;
    std::string type_tag;
    size_t sig_length_bytes;
    std::string hook_type;
};

struct SearchResult {
    fs::path file;
    size_t line_num;
    std::string content;
};

struct HexLine {
    uint64_t offset;
    std::string hex_bytes;
    std::string ascii;
};

class FileLoader {
public:
    static std::vector<FileEntry> ScanDirectory(const fs::path& root, const fs::path& subdir = "");
    static TextFileContent LoadTextFile(const fs::path& path, size_t offset = 0, size_t limit = 5000, const std::string& encoding = "utf-8");
    static std::vector<StringEntry> LoadStrings(const fs::path& path, const std::string& filter = "", size_t offset = 0, size_t limit = 100, const std::string& encoding = "utf-8");
    static std::vector<PatternEntry> LoadPatterns(const fs::path& path, const std::string& module_filter = "", const std::string& hook_type_filter = "", const std::string& query = "", size_t offset = 0, size_t limit = 50);
    static std::vector<SearchResult> SearchFiles(const fs::path& root, const std::string& query, size_t limit = 50, size_t offset = 0);
    static std::vector<HexLine> LoadHexDump(const fs::path& path, uint64_t offset = 0, size_t length = 512);
    static std::string FormatSize(uintmax_t bytes);
    static std::string EscapeHtml(const std::string& str);
    
private:
    static bool IsTextFile(const fs::path& path);
    static std::string ReadFileContent(const fs::path& path, const std::string& encoding);
};