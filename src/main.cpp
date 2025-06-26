#include <csignal>
#include <iostream>
#include <chrono>
#include <sstream>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/async.h>
#include <spdlog/async_logger.h>
#include <nlohmann/json.hpp>

#include "server.h"

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

bool set_log_level(auto logger, const std::string &level) {
    static const std::unordered_map<std::string, spdlog::level::level_enum>
        level_map = {{"trace", spdlog::level::trace},
                     {"debug", spdlog::level::debug},
                     {"info", spdlog::level::info},
                     {"warn", spdlog::level::warn},
                     {"error", spdlog::level::err},
                     {"critical", spdlog::level::critical},
                     {"off", spdlog::level::off}};

    auto it = level_map.find(level);
    if (it != level_map.end()) {
        logger->set_level(it->second);
        return true;
    }
    return false;
}

trojan::Server::Config load_config_from_env() {
    trojan::Server::Config cfg;

    const char *ip = std::getenv("TROJAN_IP");
    const char *passwd = std::getenv("TROJAN_PASSWD");
    const char *path = std::getenv("TROJAN_PATH");
    const char *ssl_crt = std::getenv("TROJAN_SSL_CRT");
    const char *ssl_key = std::getenv("TROJAN_SSL_KEY");
    const char *port_str = std::getenv("TROJAN_PORT");
    const char *worker_str = std::getenv("TROJAN_WORKERS");
    const char *timeout_str = std::getenv("TROJAN_TIMEOUT");
    const char *max_idle_str = std::getenv("TROJAN_MAX_IDLE");
    const char *dns_cache_time_str = std::getenv("TROJAN_DNS_CACHE_TIME");

    cfg.ip = ip ? ip : "0.0.0.0";
    cfg.passwd = passwd ? passwd : "";
    cfg.path = path ? path : "/";
    cfg.ssl_crt = ssl_crt ? ssl_crt : "";
    cfg.ssl_key = ssl_key ? ssl_key : "";

    cfg.port = port_str ? std::stoi(port_str) : 5555;
    cfg.worker_num = worker_str ? std::stoi(worker_str) : 4;
    cfg.timeout = timeout_str ? std::chrono::seconds(std::stoi(timeout_str))
                              : std::chrono::seconds(10);
    cfg.read_write_max_idle =
        max_idle_str ? std::chrono::seconds(std::stoi(max_idle_str))
                     : std::chrono::seconds(60);
    cfg.dns_cache_time =
        dns_cache_time_str ? std::chrono::minutes(std::stoi(dns_cache_time_str))
                           : std::chrono::minutes(30);

    return cfg;
}

namespace trojan {
std::ostream &operator<<(std::ostream &os, const Server::Config &cfg) {
    os << "Trojan Config:\n";
    os << "  IP         : " << cfg.ip << "\n";
    os << "  Port       : " << cfg.port << "\n";
    os << "  Workers    : " << cfg.worker_num << "\n";
    os << "  Password   : " << cfg.passwd << " -> " << SHA224(cfg.passwd)
       << "\n";
    os << "  Path       : " << cfg.path << "\n";
    os << "  SSL Cert   : " << cfg.ssl_crt << "\n";
    os << "  SSL Key    : " << cfg.ssl_key << "\n";
    os << "  Timeout    : " << cfg.timeout.count() << " sec\n";
    os << "  Max Idle   : " << cfg.read_write_max_idle.count() << " sec\n";
    os << "  DNS Cache  : " << cfg.dns_cache_time.count() << " min\n";
    return os;
}
}  // namespace trojan

// curl -X POST http://localhost:7777/loglevel -H "Content-Type:
// application/json" -d '{"level": "debug"}'
asio::awaitable<void> startLoggerServer(auto acceptor, auto logger_) {
    for (;;) {
        asio::ip::tcp::socket socket(co_await asio::this_coro::executor);
        auto [ec] = co_await acceptor->async_accept(socket,
                                                    asio::as_tuple(
                                                        asio::use_awaitable));
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                SPDLOG_INFO("logger server stopped");
                break;
            }
            continue;
        }

        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        if (auto [ec, bytes] = co_await http::async_read(
                socket, buffer, req, asio::as_tuple(asio::use_awaitable));
            ec) {
            SPDLOG_INFO("{}", ec.message());
            continue;
        }

        http::response<http::string_body> res;
        if (req.method() == http::verb::post && req.target() == "/loglevel") {
            try {
                auto j = nlohmann::json::parse(req.body());
                std::string level = j.at("level").get<std::string>();
                if (set_log_level(logger_, level)) {
                    res.result(http::status::ok);
                    res.body() = "Log level set to: " + level;
                } else {
                    res.result(http::status::bad_request);
                    res.body() = "Invalid log level";
                }
            } catch (...) {
                res.result(http::status::bad_request);
                res.body() = "Invalid JSON";
            }
        } else {
            res.result(http::status::not_found);
            res.body() = "Not found";
        }

        res.prepare_payload();

        co_await http::async_write(socket,
                                   res,
                                   asio::as_tuple(asio::use_awaitable));
    }
    co_return;
}

int main(int, char **argv) {
    size_t queue_size = 8192;
    size_t thread_count = 1;
    spdlog::init_thread_pool(queue_size, thread_count);

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    std::vector<spdlog::sink_ptr> sinks{console_sink};

    auto logger_ = std::make_shared<spdlog::async_logger>(
        "async_logger",
        sinks.begin(),
        sinks.end(),
        spdlog::thread_pool(),
        spdlog::async_overflow_policy::block);

    spdlog::set_default_logger(logger_);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e][thread %t][%!][%s:%#][%l] %v");

    const char *port_str = std::getenv("TROJAN_LOG_PORT");
    int port = port_str ? std::stoi(port_str) : 7777;

    auto io_context = std::make_shared<asio::io_context>();

    auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(
        *io_context,
        asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));

    trojan::Server::Config cfg = load_config_from_env();
    std::stringstream ss;
    ss << cfg;

    SPDLOG_INFO("{}", ss.str());
    auto ts = std::make_shared<trojan::Server>(cfg);

    asio::signal_set sig(*io_context, SIGINT, SIGTERM, SIGUSR1);
    sig.async_wait([=](const boost::system::error_code &ec, int signal_number) {
        SPDLOG_INFO("recv stop signal: {}", signal_number);
        ts->stop();
        acceptor->close();
        io_context->stop();
    });

    asio::co_spawn(
        *io_context,
        [](auto ts) -> asio::awaitable<void> {
            try {
                SPDLOG_INFO("start server");
                co_await ts->start();
            } catch (const std::exception &e) {
                SPDLOG_ERROR("{}", e.what());
            }
            co_return;
        }(ts),
        asio::detached);

    asio::co_spawn(*io_context,
                   startLoggerServer(acceptor, logger_),
                   asio::detached);

    io_context->run();
    return 0;
}
