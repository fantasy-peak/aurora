module;

#include <cstdint>

#include <nlohmann/json.hpp>

export module Config;

import std;
import spdlog;
import Utils;

export enum class RunType : uint8_t { SERVER, CLIENT };

NLOHMANN_JSON_SERIALIZE_ENUM(RunType,
                             {{RunType::SERVER, "server"},
                              {RunType::CLIENT, "client"}})

struct SslConfig {
    bool verify;
    std::string crt;
    std::string key;
    int32_t session_timeout;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(SslConfig, verify, crt, key, session_timeout)
};

export struct Config {
    RunType run_type;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string http_proxy;
    std::string passwd;
    SslConfig ssl;
    uint16_t threads;
    spdlog::level::level_enum log_level;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Config,
                                   run_type,
                                   local_addr,
                                   local_port,
                                   remote_addr,
                                   remote_port,
                                   http_proxy,
                                   passwd,
                                   ssl,
                                   threads,
                                   log_level)
};

export inline auto loadConfig(const std::string &file) {
    std::ifstream ifs(file);
    nlohmann::json j = nlohmann::json::parse(ifs);
    info(std::source_location::current(), "{}", j.dump(2));
    Config cfg;
    nlohmann::from_json(j, cfg);
    initLog(cfg.log_level);
    cfg.passwd = SHA224(cfg.passwd);
    return cfg;
}

namespace spdlog::level {
NLOHMANN_JSON_SERIALIZE_ENUM(spdlog::level::level_enum,
                             {{spdlog::level::level_enum::trace, "trace"},
                              {spdlog::level::level_enum::debug, "debug"},
                              {spdlog::level::level_enum::info, "info"},
                              {spdlog::level::level_enum::warn, "warn"},
                              {spdlog::level::level_enum::err, "err"},
                              {spdlog::level::level_enum::critical, "critical"},
                              {spdlog::level::level_enum::off, "off"}})
}