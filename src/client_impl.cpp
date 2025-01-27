module;

#include <openssl/ssl.h>
#include <openssl/err.h>

module TrojanClient;

import std;
import spdlog;
import boost;
import Utils;
import UdpPacket;
import TrojanRequest;
import Config;
import Cert;
import Socks5Address;
import var;

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

asio::awaitable<std::optional<std::shared_ptr<asio::ip::tcp::socket>>>
TrojanClient::createSocket(const std::string& target_ip,
                           const std::string& target_port) {
    const auto& host = m_proxy_host.empty() ? target_ip : m_proxy_host;
    const auto& port = m_proxy_port.empty() ? target_port : m_proxy_port;

    auto solver = asio::ip::tcp::resolver(co_await asio::this_coro::executor);
    auto [ec, results] =
        co_await solver.async_resolve(host, port, use_nothrow_awaitable);
    if (ec) {
        info(std::source_location::current(),
             "async_resolve: {}",
             ec.message());
        co_return std::nullopt;
    }

    asio::ip::tcp::socket socket{co_await asio::this_coro::executor};

    asio::steady_timer timer(co_await asio::this_coro::executor);
    timer.expires_after(std::chrono::seconds(10));
    auto result = co_await (
        socket.async_connect(*(results.begin()), use_nothrow_awaitable) ||
        timer.async_wait(asio::as_tuple(asio::use_awaitable)));
    if (result.index() == 0) {
        auto [ec] = std::get<0>(result);
        if (ec) {
            info(std::source_location::current(),
                 "async_connect: {}",
                 ec.message());
            co_return std::nullopt;
        }
    } else if (result.index() == 1) {
        info(std::source_location::current(),
             "connect timeout {}:{}",
             host,
             port);
        co_return std::nullopt;
    }
    setsockopt(socket);
    if (!m_proxy_host.empty()) {
        auto ret =
            co_await Http::connectHttpProxy(target_ip, target_port, socket);
        if (!ret) {
            co_return std::nullopt;
        }
        debug(std::source_location::current(),
              "proxy connected {}:{}!!!",
              host,
              port);
    }
    debug(std::source_location::current(), "connected {}:{}!!!", host, port);
    co_return std::make_shared<asio::ip::tcp::socket>(std::move(socket));
}

asio::awaitable<void> TrojanClient::session(
    std::shared_ptr<asio::ip::tcp::socket> socket) {
    ScopeExit auto_exit([=] {
        if (!socket->is_open()) {
            return;
        }
        boost::system::error_code ec;
        socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket->close(ec);
    });

    char req[2];
    auto [ec, count] = co_await asio::async_read(*socket,
                                                 asio::buffer(req, sizeof(req)),
                                                 use_nothrow_awaitable);
    if (ec) {
        if (ec != asio::error::eof)
            error(std::source_location::current(), "{}", ec.message());
        co_return;
    }
    if (req[0] != 5) {
        error(std::source_location::current(), "wrong version header");
        co_return;
    }
    debug(std::source_location::current(), "methods:{}", (int)req[1]);
    char methods[255];
    std::tie(ec, count) =
        co_await asio::async_read(*socket,
                                  asio::buffer(methods, (int)req[1]),
                                  use_nothrow_awaitable);
    if (ec) {
        error(std::source_location::current(), "{}", ec.message());
        co_return;
    }
    constexpr std::string_view ok("\x05\x00", 2);
    co_await asio::async_write(*socket,
                               asio::buffer(ok.data(), ok.size()),
                               use_nothrow_awaitable);

    char buffer[1024];
    std::tie(ec, count) = co_await asio::async_read(*socket,
                                                    asio::buffer(buffer, 4),
                                                    use_nothrow_awaitable);
    if (ec) {
        if (ec != asio::error::eof)
            error(std::source_location::current(), "{}", ec.message());
        co_return;
    }
    char cmd = buffer[1];
    auto handshake = std::format("{}\r\n{}{}", m_cfg.passwd, cmd, buffer[3]);
    if (buffer[3] == 0x01) {
        debug(std::source_location::current(), "ipv4");
        // 一个4字节的ipv4地址
        co_await asio::async_read(*socket,
                                  asio::buffer(buffer, 4),
                                  use_nothrow_awaitable);
        handshake.append(buffer, 4);
    } else if (buffer[3] == 0x03) {
        co_await asio::async_read(*socket,
                                  asio::buffer(buffer, 1),
                                  use_nothrow_awaitable);

        // 一个可变长度的域名，这种情况下DST.ADDR的第一个字节表示域名长度
        auto length = static_cast<uint8_t>(buffer[0]);
        debug(std::source_location::current(), "domain: {}", length);
        handshake.append(buffer, 1);
        co_await asio::async_read(*socket,
                                  asio::buffer(buffer, length),
                                  use_nothrow_awaitable);
        handshake.append(buffer, length);
    } else if (buffer[3] == 0x04) {
        debug(std::source_location::current(), "ipv6");
        // 一个16字节的ipv6地址
        co_await asio::async_read(*socket,
                                  asio::buffer(buffer, 16),
                                  use_nothrow_awaitable);
        handshake.append(buffer, 16);
    }
    // read port
    co_await asio::async_read(*socket,
                              asio::buffer(buffer, 2),
                              use_nothrow_awaitable);
    handshake.append(buffer, 2);
    handshake.append("\r\n");

    auto sock_opt = co_await createSocket(m_cfg.remote_addr,
                                          std::to_string(m_cfg.remote_port));
    if (!sock_opt.has_value())
        co_return;
    auto& out_socket = sock_opt.value();

    auto ssl_socket =
        std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(
            std::move(*out_socket), m_ssl_context);

    ScopeExit ssl_auto_exit([ssl_socket] {
        asio::co_spawn(ssl_socket->get_executor(),
                       async_shutdown(ssl_socket),
                       asio::detached);
    });

    if (!SSL_set_tlsext_host_name(ssl_socket->native_handle(),
                                  m_cfg.remote_addr.c_str())) {
        ec = boost::system::error_code(static_cast<int>(::ERR_get_error()),
                                       asio::error::get_ssl_category());
        error(std::source_location::current(), "connect: {}", ec.message());
        co_return;
    }
    if (auto [ec] =
            co_await ssl_socket->async_handshake(asio::ssl::stream_base::client,
                                                 use_nothrow_awaitable);
        ec) {
        error(std::source_location::current(),
              "async_handshake: {}",
              ec.message());
        co_return;
    }
    // 发送握手包
    co_await asio::async_write(*ssl_socket,
                               asio::buffer(handshake.data(), handshake.size()),
                               use_nothrow_awaitable);
    if (cmd == 0x01) {
        constexpr std::string_view ok_s5(
            "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);
        co_await asio::async_write(*socket,
                                   asio::buffer(ok_s5.data(), ok_s5.size()),
                                   use_nothrow_awaitable);
        co_await (forward(socket, ssl_socket) || forward(ssl_socket, socket));
    } else if (cmd == 0x03) {
        asio::ip::udp::endpoint bindpoint(socket->local_endpoint().address(),
                                          0);
        boost::system::error_code ec;
        auto udp_socket = std::make_shared<asio::ip::udp::socket>(
            co_await asio::this_coro::executor);
        udp_socket->open(bindpoint.protocol(), ec);
        if (ec) {
            error(std::source_location::current(), "{}", ec.message());
            co_return;
        }
        udp_socket->bind(bindpoint);

        auto ok_s5 = std::string("\x05\x00\x00", 3) +
                     Socks5Address::generate(udp_socket->local_endpoint());
        co_await asio::async_write(*socket,
                                   asio::buffer(ok_s5.data(), ok_s5.size()),
                                   use_nothrow_awaitable);

        auto udp_recv_endpoint = std::make_shared<asio::ip::udp::endpoint>();

        auto udp_to_trojan =
            [](auto ssl_socket,
               auto udp_socket,
               auto udp_recv_endpoint) -> asio::awaitable<void> {
            char udp_read_buf[BUFFER_SIZE];
            std::string data;
            for (;;) {
                auto [ec, len] = co_await udp_socket->async_receive_from(
                    asio::buffer(udp_read_buf, BUFFER_SIZE),
                    *udp_recv_endpoint,
                    use_nothrow_awaitable);
                if (ec) {
                    error(std::source_location::current(), "{}", ec.message());
                    break;
                }
                data.append(udp_read_buf, len);
                Socks5Address address;
                size_t address_len;
                bool is_addr_valid = address.parse(data.substr(3), address_len);
                if (!is_addr_valid) {
                    error(std::source_location::current(), "bad UDP packet");
                    break;
                }
                size_t length = data.length() - 3 - address_len;
                std::string packet = data.substr(3, address_len) +
                                     char(uint8_t(length >> 8)) +
                                     char(uint8_t(length & 0xFF)) + "\r\n" +
                                     data.substr(address_len + 3);
                info(std::source_location::current(),
                     "send udp package: {}",
                     packet.size());
                co_await asio::async_write(*ssl_socket,
                                           asio::buffer(packet.data(),
                                                        packet.size()),
                                           use_nothrow_awaitable);
            }
        };

        auto trojan_to_udp =
            [](auto ssl_socket,
               auto udp_socket,
               auto udp_recv_endpoint) -> asio::awaitable<void> {
            std::string udp_data_buf;
            char buffer[BUFFER_SIZE];
            for (;;) {
                auto [ec, length] = co_await ssl_socket->async_read_some(
                    asio::buffer(buffer, sizeof(buffer)),
                    use_nothrow_awaitable);
                udp_data_buf.append(buffer, length);
                UdpPacket packet;
                size_t packet_len;
                bool is_packet_valid = packet.parse(udp_data_buf, packet_len);
                if (!is_packet_valid) {
                    if (udp_data_buf.length() > MAX_LEN) {
                        error(std::source_location::current(),
                              "UDP packet too long");
                        break;
                    }
                    continue;
                }
                Socks5Address address;
                size_t address_len;
                bool is_addr_valid = address.parse(udp_data_buf, address_len);
                if (!is_addr_valid) {
                    error(std::source_location::current(),
                          "invalid UDP packet address");
                    break;
                }
                auto reply = std::string("\x00\x00\x00", 3) +
                             udp_data_buf.substr(0, address_len) +
                             packet.payload;
                udp_data_buf = udp_data_buf.substr(packet_len);
                std::tie(ec, length) = co_await udp_socket->async_send_to(
                    boost::asio::buffer(reply.c_str(), reply.size()),
                    *udp_recv_endpoint,
                    use_nothrow_awaitable);
                if (ec) {
                    info(std::source_location::current(), "{}", ec.message());
                    break;
                }
            }
        };

        co_await (udp_to_trojan(ssl_socket, udp_socket, udp_recv_endpoint) ||
                  trojan_to_udp(ssl_socket, udp_socket, udp_recv_endpoint));

        if (udp_socket->is_open()) {
            boost::system::error_code ec;
            udp_socket->cancel(ec);
            udp_socket->close(ec);
        }
        co_return;
    }
}

TrojanClient::TrojanClient(const Config& config)
    : m_cfg(config), m_ssl_context(asio::ssl::context::tlsv13_client) {
    boost::system::error_code ec;
    load_root_certificates(m_ssl_context, ec);

    if (!m_cfg.http_proxy.empty()) {
        info(std::source_location::current(),
             "parse http proxy: {}",
             m_cfg.http_proxy);
        boost::urls::url url(m_cfg.http_proxy);
        m_proxy_host = url.host();
        m_proxy_port = url.port();
        info(std::source_location::current(),
             "{}:{}",
             m_proxy_host,
             m_proxy_port);
    }

    m_ssl_context.set_verify_mode(m_cfg.ssl.verify ? SSL_VERIFY_PEER
                                                   : SSL_VERIFY_NONE);

    if (config.ssl.session_timeout > 0) {
        info(std::source_location::current(),
             "set SSL_SESS_CACHE_CLIENT: {}",
             m_cfg.ssl.session_timeout);
        auto native = m_ssl_context.native_handle();
        SSL_CTX_set_session_cache_mode(native, SSL_SESS_CACHE_CLIENT);
        SSL_CTX_set_timeout(native, m_cfg.ssl.session_timeout);
    }

    m_network = std::make_unique<Network>(
        config,
        [this](asio::ip::tcp::socket socket) mutable -> asio::awaitable<void> {
            co_await session(
                std::make_shared<asio::ip::tcp::socket>(std::move(socket)));
        });
}

void TrojanClient::run() {
    m_network->run();
}
