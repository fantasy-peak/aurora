module;

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

export module spdlog;

import std;

export namespace spdlog::level {
using spdlog::level::level_enum;
}

export void initLog(auto level) {
    spdlog::set_level(level);
}

export template <typename... Args>
void error(const std::source_location &location,
           std::format_string<Args...> fmt,
           Args &&...args) {
    auto str = std::format(fmt, std::forward<Args>(args)...);
    std::filesystem::path file_path = location.file_name();
    spdlog::error("[{}:{}] {}",
                  file_path.filename().string(),
                  location.line(),
                  str);
}

export template <typename... Args>
void info(const std::source_location &location,
          std::format_string<Args...> fmt,
          Args &&...args) {
    auto str = std::format(fmt, std::forward<Args>(args)...);
    std::filesystem::path file_path = location.file_name();
    spdlog::info("[{}:{}] {}",
                 file_path.filename().string(),
                 location.line(),
                 str);
}

export template <typename... Args>
void debug(const std::source_location &location,
           std::format_string<Args...> fmt,
           Args &&...args) {
    auto str = std::format(fmt, std::forward<Args>(args)...);
    std::filesystem::path file_path = location.file_name();
    spdlog::debug("[{}:{}] {}",
                  file_path.filename().string(),
                  location.line(),
                  str);
}

export template <typename... Args>
void trace(const std::source_location &location,
           std::format_string<Args...> fmt,
           Args &&...args) {
    auto str = std::format(fmt, std::forward<Args>(args)...);
    std::filesystem::path file_path = location.file_name();
    spdlog::trace("[{}:{}] {}",
                  file_path.filename().string(),
                  location.line(),
                  str);
}