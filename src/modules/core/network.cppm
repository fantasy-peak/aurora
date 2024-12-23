module;

#include <sys/socket.h>
#include <netinet/tcp.h>

#include <openssl/ssl.h>

export module Network;

import std;
import boost;
import spdlog;
import Config;
import Utils;

export class Network {
  public:
    Network(
        const Config& config,
        std::function<asio::awaitable<void>(asio::ip::tcp::socket)> callback)
        : m_cfg(config),
          m_callback(std::move(callback)),
          m_pool(config.threads) {
    }

    asio::awaitable<void> start() {
        asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(
                                             m_cfg.local_addr),
                                         m_cfg.local_port);
        asio::ip::tcp::acceptor acceptor(co_await asio::this_coro::executor);
        acceptor.open(endpoint.protocol());
        boost::system::error_code ec;
#ifdef __linux__
        using fast_open =
            asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
        acceptor.set_option(fast_open(5), ec);
        info(std::source_location::current(),
             "start fastopen {}",
             ec.message());
#endif
        acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        acceptor.bind(endpoint);
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            error(std::source_location::current(), "{}", ec.message());
            co_return;
        }
        for (;;) {
            auto& context = m_pool.getIoContext();
            asio::ip::tcp::socket socket(context);
            auto [ec] = co_await acceptor.async_accept(
                socket, asio::as_tuple(boost::asio::use_awaitable));
            if (ec) {
                if (ec == asio::error::operation_aborted)
                    break;
                continue;
            }
            auto endpoint = socket.remote_endpoint(ec);
            if (!ec) {
                std::stringstream ss;
                ss << endpoint;
                debug(std::source_location::current(),
                      "new connection from: [{}]",
                      ss.str());
            }
            socket.set_option(asio::socket_base::keep_alive(true));
            socket.set_option(asio::ip::tcp::no_delay(true));
            asio::co_spawn(context,
                           m_callback(std::move(socket)),
                           asio::detached);
        }
    }

    void run() {
        m_pool.start();
        asio::co_spawn(m_ioc, start(), asio::detached);
        m_ioc.run();
    }

    Config m_cfg;
    std::function<asio::awaitable<void>(asio::ip::tcp::socket)> m_callback;
    IoContextPool m_pool;
    asio::io_context m_ioc;
};
