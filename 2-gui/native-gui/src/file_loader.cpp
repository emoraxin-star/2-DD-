#include "file_loader.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <json.hpp>

namespace fs = std::filesystem;

std::vector<FileEntry> FileLoader::ScanDirectory(const fs::path& root, const fs::path& subdir) {
    std::vector<FileEntry> entries;
    fs::path target = root / subdir;
    if (!fs::exists(target) || !fs::is_directory(target)) return entries;
    
    auto sys_now = std::chrono::system_clock::now();
    auto file_now = fs::file_time_type::clock::now();
    
    for (const auto& entry : fs::directory_iterator(target)) {
        FileEntry fe;
        fe.path = entry.path();
        fe.relative_path = fs::relative(entry.path(), root);
        fe.is_directory = entry.is_directory();
        fe.size = entry.is_regular_file() ? entry.file_size() : 0;
        auto ft = entry.last_write_time();
        fe.modified = std::chrono::system_clock::to_time_t(sys_now + (ft - file_now));
        entries.push_back(fe);
    }
    
    std::sort(entries.begin(), entries.end(), [](const FileEntry& a, const FileEntry& b) {
        if (a.is_directory != b.is_directory) return a.is_directory > b.is_directory;
        return a.relative_path.filename().string() < b.relative_path.filename().string();
    });
    
    return entries;
}

TextFileContent FileLoader::LoadTextFile(const fs::path& path, size_t offset, size_t limit, const std::string& encoding) {
    TextFileContent result;
    result.file_size = fs::file_size(path);
    result.is_binary = !IsTextFile(path);
    if (result.is_binary) return result;
    
    std::string content = ReadFileContent(path, encoding);
    std::istringstream iss(content);
    std::string line;
    size_t current = 0;
    while (std::getline(iss, line)) {
        result.total_lines++;
        if (current >= offset && result.lines.size() < limit) {
            result.lines.push_back(line);
        }
        current++;
    }
    return result;
}

std::vector<StringEntry> FileLoader::LoadStrings(const fs::path& path, const std::string& filter, size_t offset, size_t limit, const std::string& encoding) {
    std::vector<StringEntry> results;
    std::string content = ReadFileContent(path, encoding);
    std::istringstream iss(content);
    std::string line;
    std::string filter_lower = filter;
    std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(),
        [](unsigned char c) { return (unsigned char)std::tolower(c); });
    
    size_t line_num = 0;
    while (std::getline(iss, line)) {
        if (line_num >= offset) {
            std::string line_lower = line;
            std::transform(line_lower.begin(), line_lower.end(), line_lower.begin(),
                [](unsigned char c) { return (unsigned char)std::tolower(c); });
            if (filter.empty() || line_lower.find(filter_lower) != std::string::npos) {
                results.push_back({line_num, line});
                if (results.size() >= limit) break;
            }
        }
        line_num++;
    }
    return results;
}

std::vector<PatternEntry> FileLoader::LoadPatterns(const fs::path& path, const std::string& module_filter, const std::string& hook_type_filter, const std::string& query, size_t offset, size_t limit) {
    std::vector<PatternEntry> results;
    std::ifstream file(path);
    if (!file.is_open()) return results;
    
    nlohmann::json root;
    try {
        file >> root;
    } catch (...) {
        return results;
    }
    
    for (const auto& item : root) {
        std::string mod = item.value("module", "");
        std::string hook = item.value("hook_type", "");
        std::string name = item.value("name", "");
        std::string sig = item.value("signature", "");
        std::string tag = item.value("type_tag", "");
        size_t sig_len = item.value("sig_length_bytes", 0);
        size_t off = item.value("offset", 0);
        
        if (!module_filter.empty() && mod != module_filter) continue;
        if (!hook_type_filter.empty() && hook != hook_type_filter) continue;
        if (!query.empty()) {
            std::string q = query;
            std::transform(q.begin(), q.end(), q.begin(),
                [](unsigned char c) { return (unsigned char)std::tolower(c); });
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                [](unsigned char c) { return (unsigned char)std::tolower(c); });
            if (lower_name.find(q) == std::string::npos) continue;
        }
        
        if (results.size() >= offset + limit) return results;
        if (results.size() >= offset) {
            results.push_back({off, sig, name, mod, tag, sig_len, hook});
        }
    }
    return results;
}

std::vector<SearchResult> FileLoader::SearchFiles(const fs::path& root, const std::string& query, size_t limit, size_t offset) {
    std::vector<SearchResult> results;
    std::string query_lower = query;
    std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(),
        [](unsigned char c) { return (unsigned char)std::tolower(c); });
    
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        std::string ext = entry.path().extension().string();
        if (ext == ".bin" || ext == ".dll" || ext == ".vsidx" || ext == ".sqlite" || ext == ".wsuo") continue;
        
        std::ifstream file(entry.path());
        if (!file.is_open()) continue;
        
        std::string line;
        size_t line_num = 0;
        while (std::getline(file, line)) {
            line_num++;
            std::string line_lower = line;
            std::transform(line_lower.begin(), line_lower.end(), line_lower.begin(),
                [](unsigned char c) { return (unsigned char)std::tolower(c); });
            if (line_lower.find(query_lower) != std::string::npos) {
                if (results.size() >= offset + limit) return results;
                if (results.size() >= offset) {
                    results.push_back({fs::relative(entry.path(), root), line_num, line.substr(0, 200)});
                }
            }
        }
    }
    return results;
}

std::vector<HexLine> FileLoader::LoadHexDump(const fs::path& path, uint64_t offset, size_t length) {
    std::vector<HexLine> lines;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return lines;
    
    file.seekg(offset, std::ios::beg);
    std::vector<uint8_t> buffer(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    size_t actual = file.gcount();
    
    for (size_t i = 0; i < actual; i += 16) {
        HexLine hl;
        hl.offset = offset + i;
        size_t chunk_size = (std::min)(16, (int)(actual - i));
        
        std::ostringstream hex_ss, ascii_ss;
        for (size_t j = 0; j < chunk_size; j++) {
            hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i + j] << " ";
            uint8_t c = buffer[i + j];
            ascii_ss << (char)((c >= 32 && c < 127) ? c : '.');
        }
        
        hl.hex_bytes = hex_ss.str();
        hl.ascii = ascii_ss.str();
        lines.push_back(hl);
    }
    return lines;
}

std::string FileLoader::FormatSize(uintmax_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    double kb = bytes / 1024.0;
    if (kb < 1024.0) return std::to_string(kb).substr(0, 4) + " KB";
    return std::to_string(kb / 1024.0).substr(0, 4) + " MB";
}

std::string FileLoader::EscapeHtml(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&#39;"; break;
            default: result += c;
        }
    }
    return result;
}

bool FileLoader::IsTextFile(const fs::path& path) {
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(),
        [](unsigned char c) { return (unsigned char)std::tolower(c); });
    static const std::set<std::string> text_exts = {
        ".txt", ".json", ".md", ".py", ".ps1", ".cpp", ".h", ".hpp", ".c",
        ".js", ".ts", ".html", ".css", ".xml", ".yaml", ".yml", ".ini", ".cfg",
        ".log", ".csv", ".sql", ".sh", ".bat", ".cmd"
    };
    return text_exts.count(ext) > 0;
}

std::string FileLoader::ReadFileContent(const fs::path& path, const std::string&) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}
