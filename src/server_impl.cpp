module;

#include <openssl/ssl.h>

module TrojanServer;

import std;
import spdlog;
import boost;
import Utils;
import UdpPacket;
import TrojanRequest;
import Config;
import var;

asio::awaitable<void> http301(
    auto& socket,
    const std::string& url = "https://www.baidu.com") {
    auto res_str = Http::createHttp301(url);
    co_await asio::async_write(*socket,
                               asio::buffer(res_str.c_str(), res_str.size()),
                               asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<void> forward(auto& from_socket, auto& to_socket) {
    char buff[BUFFER_SIZE];
    asio::steady_timer timer(co_await asio::this_coro::executor);
    for (;;) {
        timer.expires_after(std::chrono::minutes(30));
        auto result = co_await (
            from_socket->async_read_some(asio::buffer(buff, sizeof(buff)),
                                         use_nothrow_awaitable) ||
            timer.async_wait(asio::as_tuple(asio::use_awaitable)));
        if (result.index() == 0) {
            auto [ec, length] = std::get<0>(result);
            if (ec) {
                break;
            }
            if (auto [ec, len] =
                    co_await asio::async_write(*to_socket,
                                               asio::buffer(buff, length),
                                               use_nothrow_awaitable);
                ec) {
                break;
            }
        } else if (result.index() == 1) {
            break;
        }
    }
    co_return;
}

asio::awaitable<void> udp_to_tcp(auto tcp_socket, auto udp_socket) {
    asio::ip::udp::endpoint udp_recv_endpoint;
    char buff[BUFFER_SIZE];
    for (;;) {
        auto [ec, len] =
            co_await udp_socket->async_receive_from(asio::buffer(buff,
                                                                 sizeof(buff)),
                                                    udp_recv_endpoint,
                                                    use_nothrow_awaitable);
        if (ec) {
            debug(std::source_location::current(), "{}", ec.message());
            co_return;
        }
        auto data =
            UdpPacket::generate(udp_recv_endpoint, std::string(buff, len));
        if (auto [ec, len] = co_await asio::async_write(*tcp_socket,
                                                        asio::buffer(data),
                                                        use_nothrow_awaitable);
            ec) {
            debug(std::source_location::current(), "{}", ec.message());
            break;
        }
    }
};

asio::awaitable<void> TrojanServer::session(
    std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket) {
    ScopeExit ssl_auto_exit([socket] {
        asio::co_spawn(socket->get_executor(),
                       async_shutdown(socket),
                       asio::detached);
    });

    if (auto [ec] = co_await socket->async_handshake(
            boost::asio::ssl::stream_base::server, use_nothrow_awaitable);
        ec) {
        error(std::source_location::current(), "{}", ec.message());
        co_return;
    }

    asio::steady_timer timer(co_await asio::this_coro::executor);
    TrojanRequest req;
    std::string request;
    char buffer[BUFFER_SIZE];
    for (;;) {
        timer.expires_after(std::chrono::seconds(30));
        auto result = co_await (
            socket->async_read_some(asio::buffer(buffer, sizeof(buffer)),
                                    use_nothrow_awaitable) ||
            timer.async_wait(asio::as_tuple(asio::use_awaitable)));
        if (result.index() == 0) {
            auto [ec, length] = std::get<0>(result);
            if (ec) {
                error(std::source_location::current(), "{}", ec.message());
                co_return;
            }
            request.append(buffer, length);
            if (req.parse(request) != -1) {
                break;
            }
            if (request.size() >= 56 && req.password != m_cfg.passwd) {
                error(std::source_location::current(),
                      "invalid passwd: {}",
                      req.password);
                co_await http301(socket);
                co_return;
            }
            if (request.size() > MAX_LEN) {
                error(std::source_location::current(), "invalid Command");
                co_await http301(socket);
                co_return;
            }
        } else if (result.index() == 1) {
            error(std::source_location::current(), "timeout");
            co_await http301(socket);
            co_return;
        }
    }
    if (req.command == TrojanRequest::Command::CONNECT) {
        auto out_socket = std::make_shared<asio::ip::tcp::socket>(
            co_await asio::this_coro::executor);

        ScopeExit auto_exit([=] {
            if (!out_socket->is_open()) {
                return;
            }
            boost::system::error_code ec;
            out_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both,
                                 ec);
            out_socket->close(ec);
        });

        auto solver =
            asio::ip::tcp::resolver(co_await asio::this_coro::executor);
        auto [ec, results] =
            co_await solver.async_resolve(req.address.address,
                                          std::to_string(req.address.port),
                                          use_nothrow_awaitable);
        if (ec) {
            error(std::source_location::current(),
                  "async_resolve: {}",
                  ec.message());
            co_return;
        }
        timer.expires_after(std::chrono::seconds(30));
        auto result = co_await (
            out_socket->async_connect(*(results.begin()), use_nothrow_awaitable) ||
            timer.async_wait(asio::as_tuple(asio::use_awaitable)));
        if (result.index() == 0) {
            auto [ec] = std::get<0>(result);
            if (ec) {
                error(std::source_location::current(),
                      "connect:{}",
                      ec.message());
                co_return;
            }
        } else if (result.index() == 1) {
            error(std::source_location::current(),
                  "connect {}:{} timeout",
                  req.address.address,
                  req.address.port);
            co_return;
        }

        if (!req.payload.empty()) {
            if (auto [ec, len] =
                    co_await asio::async_write(*out_socket,
                                               asio::buffer(req.payload.data(),
                                                            req.payload.size()),
                                               use_nothrow_awaitable);
                ec) {
                error(std::source_location::current(),
                      "async_write: {}",
                      ec.message());
                co_return;
            }
        }
        co_await (forward(socket, out_socket) || forward(out_socket, socket));
        co_return;
    }
#if 0
    for (char c : req.payload) {
        int ascii_value = static_cast<int>(c);
        std::cout << "Character: " << c << ", ASCII: " << ascii_value
                  << ", Hex: " << std::hex << std::setw(2) << std::setfill('0')
                  << ascii_value << std::endl;
    }
#endif
    auto udp_socket = std::make_shared<asio::ip::udp::socket>(
        co_await asio::this_coro::executor);

    co_await [](auto payload,
                auto tcp_socket,
                auto udp_socket) -> asio::awaitable<void> {
        char buff[BUFFER_SIZE];
        asio::steady_timer timer(co_await asio::this_coro::executor);
        for (;;) {
            UdpPacket packet;
            size_t packet_len;
            bool is_packet_valid = packet.parse(payload, packet_len);
            if (!is_packet_valid) {
                timer.expires_after(std::chrono::minutes(30));
                auto result = co_await (
                    tcp_socket->async_read_some(asio::buffer(buff,
                                                             sizeof(buff)),
                                                use_nothrow_awaitable) ||
                    timer.async_wait(asio::as_tuple(asio::use_awaitable)));
                if (result.index() == 0) {
                    auto [ec, length] = std::get<0>(result);
                    if (ec) {
                        debug(std::source_location::current(),
                              "{}",
                              ec.message());
                        break;
                    }
                    payload.append(buff, length);
                    if (payload.length() > MAX_LEN) {
                        co_await http301(tcp_socket);
                        break;
                    }
                } else if (result.index() == 1) {
                    error(std::source_location::current(), "read timeout");
                    break;
                }
            } else {
                payload = payload.substr(packet_len);
                debug(std::source_location::current(),
                      "query_addr: [{}]",
                      packet.address.address);
                asio::ip::udp::resolver udp_resolver(
                    co_await asio::this_coro::executor);
                auto [err, results] = co_await udp_resolver.async_resolve(
                    packet.address.address,
                    std::to_string(packet.address.port),
                    use_nothrow_awaitable);
                if (err || results.empty()) {
                    error(std::source_location::current(), "{}", err.message());
                    break;
                }
                auto iterator = results.begin();
                if (!udp_socket->is_open()) {
                    auto protocol = iterator->endpoint().protocol();
                    boost::system::error_code ec;
                    udp_socket->open(protocol, ec);
                    if (ec) {
                        break;
                    }
                    udp_socket->bind(asio::ip::udp::endpoint(protocol, 0));
                    asio::co_spawn(co_await asio::this_coro::executor,
                                   udp_to_tcp(tcp_socket, udp_socket),
                                   asio::detached);
                }
                auto [ec, len] = co_await udp_socket->async_send_to(
                    boost::asio::buffer(packet.payload.c_str(),
                                        packet.payload.size()),
                    *iterator,
                    use_nothrow_awaitable);
                if (ec) {
                    info(std::source_location::current(), "{}", ec.message());
                    break;
                }
            }
        }
        if (udp_socket->is_open()) {
            boost::system::error_code ec;
            udp_socket->cancel(ec);
            udp_socket->close(ec);
        }
    }(std::move(req.payload), socket, udp_socket);

    co_return;
}

TrojanServer::TrojanServer(const Config& config)
    : m_cfg(config), m_ssl_context(asio::ssl::context::tlsv13_server) {
    m_ssl_context.set_options(
        asio::ssl::context::default_workarounds | asio::ssl::context::no_tlsv1 |
        asio::ssl::context::no_tlsv1_1 | asio::ssl::context::no_tlsv1_2);

    if (config.ssl.session_timeout > 0) {
        info(std::source_location::current(),
             "set SSL_SESS_CACHE_SERVER: {}",
             m_cfg.ssl.session_timeout);
        auto native = m_ssl_context.native_handle();
        SSL_CTX_set_session_cache_mode(native, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_timeout(native, m_cfg.ssl.session_timeout);
    }

    boost::system::error_code ec;
    [[maybe_unused]] auto ret1 =
        m_ssl_context.use_certificate_chain_file(m_cfg.ssl.crt, ec);
    [[maybe_unused]] auto ret2 =
        m_ssl_context.use_private_key_file(m_cfg.ssl.key,
                                           asio::ssl::context::pem,
                                           ec);

    m_network = std::make_unique<Network>(
        config,
        [this](asio::ip::tcp::socket socket) mutable -> asio::awaitable<void> {
            co_await session(
                std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(
                    std::move(socket), m_ssl_context));
        });
}

void TrojanServer::run() {
    m_network->run();
}
