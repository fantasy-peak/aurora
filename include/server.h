#pragma once

#include <expected>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>

#include "io_ctx_pool.h"
#include "trojan_request.h"
#include "dns_resolver.h"
#include "utils.h"

namespace trojan {

class Server final {
  public:
    enum class ParseError : int8_t { NetworkError, PasswordError };

    struct Config {
        std::string ip;
        uint16_t port;
        uint16_t worker_num{4};
        std::string ssl_crt;
        std::string ssl_key;
        std::string passwd;
        std::string path;
        std::chrono::seconds timeout{10};
        std::chrono::seconds read_write_max_idle{60};
        std::chrono::minutes dns_cache_time{30};
    };

    Server(const Config &cfg);

    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;
    Server(Server &&) = delete;
    Server &operator=(Server &&) = delete;

    asio::awaitable<void> start();
    void stop();

  private:
    asio::awaitable<void> dns();
    asio::awaitable<void> handshake(
        std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket);
    asio::awaitable<void> session(
        std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket);
    asio::awaitable<std::expected<TrojanRequest, Server::ParseError>>
    recvRequest(
        std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> &socket,
        std::shared_ptr<std::chrono::steady_clock::time_point> &deadline,
        std::string &request,
        Server::Config &cfg);
    asio::awaitable<std::optional<
        std::vector<asio::ip::tcp::resolver::results_type::value_type>>>
    resolve(const TrojanRequest &req);

    Config m_cfg;
    asio::ip::tcp::endpoint m_ep;
    std::shared_ptr<IoCtxPool> m_io_ctx_pool;
    asio::ssl::context m_ssl_context{asio::ssl::context::tlsv13_server};
    std::shared_ptr<DnsResolver> m_dns_resolver;
    std::unique_ptr<asio::ip::tcp::acceptor> m_acceptor;
    std::mutex m_mtx;
    std::unique_ptr<asio::steady_timer> m_timer;

    struct CachedResult {
        std::vector<asio::ip::tcp::resolver::results_type::value_type> results;
        std::chrono::steady_clock::time_point expire_time{
            std::chrono::steady_clock::now()};
    };

    std::unordered_map<std::string, CachedResult> m_results;
};

}  // namespace trojan