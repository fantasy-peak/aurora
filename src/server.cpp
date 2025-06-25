#include <expected>
#include <memory>
#include <string>

#include <spdlog/spdlog.h>

#include "server.h"
#include "trojan_request.h"
#include "udp_packet.h"

namespace trojan {

template <typename F, typename T>
asio::awaitable<void> forward(
    F from_socket,
    T to_socket,
    std::shared_ptr<std::chrono::steady_clock::time_point> deadline,
    Server::Config &cfg) {
    std::vector<char> buffer(32 * 1024);
    for (;;) {
        *deadline = std::chrono::steady_clock::now() + cfg.read_write_max_idle;
        auto [ec, length] = co_await from_socket->async_read_some(
            asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
        if (ec) {
            break;
        }
        // TROJAN_INFO_LOG("forward {} bytes", length);
        if (auto [ec, len] =
                co_await asio::async_write(*to_socket,
                                           asio::buffer(buffer, length),
                                           asio::as_tuple(asio::use_awaitable));
            ec) {
            break;
        }
    }
    co_return;
}

long long getCurrentTimestampMs() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               now.time_since_epoch())
        .count();
}

asio::awaitable<void> timeout(std::chrono::steady_clock::duration duration) {
    asio::steady_timer timer(co_await asio::this_coro::executor);
    timer.expires_after(duration);
    co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<void> watchdog(
    std::shared_ptr<std::chrono::steady_clock::time_point> deadline) {
    asio::steady_timer timer(co_await asio::this_coro::executor);

    auto now = std::chrono::steady_clock::now();
    while (*deadline > now) {
        timer.expires_at(*deadline);
        co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        now = std::chrono::steady_clock::now();
    }
    co_return;
}

asio::awaitable<void> http301(
    auto &socket,
    const std::string &url = "https://www.baidu.com") {
    namespace http = boost::beast::http;
    http::response<http::empty_body> res{http::status::moved_permanently, 11};
    res.set(http::field::location, url);
    res.set(http::field::server, "nginx/1.20.1");
    std::stringstream ss;
    ss << res;
    auto res_str = ss.str();
    co_await asio::async_write(*socket,
                               asio::buffer(res_str.c_str(), res_str.size()),
                               asio::as_tuple(asio::use_awaitable));
}

Server::Server(const Config &cfg)
    : m_cfg(cfg),
      m_ep(asio::ip::make_address(cfg.ip), cfg.port),
      m_io_ctx_pool(std::make_shared<IoCtxPool>(cfg.worker_num)) {
    m_io_ctx_pool->createMainContext();
    m_io_ctx_pool->start();
    m_cfg.passwd = SHA224(m_cfg.passwd);
    asio::co_spawn(*m_io_ctx_pool->getMainContext(), dns(), asio::detached);
    initSsl();
}

asio::awaitable<void> Server::dns() {
    m_timer =
        std::make_unique<asio::steady_timer>(*m_io_ctx_pool->getMainContext());
    for (;;) {
        m_timer->expires_after(std::chrono::minutes(2));
        auto [ec] =
            co_await m_timer->async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec) {
            break;
        }
        std::unique_lock<std::mutex> l(m_mtx);
        std::erase_if(m_results, [&](auto &p) {
            auto &[addr, cached_result] = p;
            return std::chrono::steady_clock::now() -
                       cached_result.expire_time >
                   m_cfg.dns_cache_time;
        });
        l.unlock();
    }
}

void Server::initSsl() {
    if (m_cfg.ssl_crt.empty() || m_cfg.ssl_key.empty())
        return;

    uint64_t opts =
        asio::ssl::context::default_workarounds | asio::ssl::context::no_tlsv1 |
        asio::ssl::context::no_tlsv1_1 | asio::ssl::context::no_tlsv1_2;

    m_ssl_context.set_options(opts);

    boost::system::error_code ec;
    [[maybe_unused]]
    auto ret = m_ssl_context.use_certificate_chain_file(m_cfg.ssl_crt, ec);
    if (ec)
        throw std::runtime_error(ec.message());

    [[maybe_unused]] auto _ =
        m_ssl_context.use_private_key_file(m_cfg.ssl_key,
                                           asio::ssl::context::pem,
                                           ec);
    if (ec)
        throw std::runtime_error(ec.message());

    auto native = m_ssl_context.native_handle();
    SSL_CTX_set_session_cache_mode(native, SSL_SESS_CACHE_SERVER);
}

asio::awaitable<void> Server::start() {
    m_acceptor = std::make_unique<asio::ip::tcp::acceptor>(
        *m_io_ctx_pool->getMainContext());
    m_acceptor->open(m_ep.protocol());
    boost::system::error_code ec;
    m_acceptor->set_option(asio::ip::tcp::acceptor::reuse_address(true));
    [[maybe_unused]] auto _ = m_acceptor->bind(m_ep, ec);
    if (ec) {
        spdlog::error("bind: {}", ec.message());
        throw std::runtime_error(ec.message());
    }
    _ = m_acceptor->listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        spdlog::error("listen: {}", ec.message());
        throw std::runtime_error(ec.message());
    }
    for (;;) {
        auto &context = m_io_ctx_pool->getIoContextPtr();
        asio::ip::tcp::socket socket(*context);
        auto [ec] = co_await m_acceptor->async_accept(socket,
                                                      asio::as_tuple(
                                                          asio::use_awaitable));
        if (ec) {
            if (ec == asio::error::operation_aborted)
                break;
            continue;
        }
        auto endpoint = socket.remote_endpoint(ec);
        if (!ec) {
            spdlog::debug("new connection from [{}:{}]",
                          endpoint.address().to_string(),
                          endpoint.port());
        }
        socket.set_option(asio::socket_base::keep_alive(true));

        auto stream =
            std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(
                std::move(socket), m_ssl_context);

        asio::co_spawn(*context, handshake(std::move(stream)), asio::detached);
    }
    co_return;
}

asio::awaitable<void> Server::handshake(
    std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket) {
    auto result = co_await (
        socket->async_handshake(boost::asio::ssl::stream_base::server,
                                asio::as_tuple(asio::use_awaitable)) ||
        timeout(m_cfg.timeout));
    if (result.index() == 1) {
        spdlog::error("async_handshake timeout");
        co_return;
    }
    auto [ec] = std::get<0>(result);
    if (ec) {
        spdlog::error("async_handshake: {}", ec.message());
        co_return;
    }
    asio::co_spawn(socket->get_executor(), session(socket), asio::detached);
}

asio::awaitable<std::expected<TrojanRequest, Server::ParseError>> Server::
    recvRequest(
        std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> &socket,
        std::shared_ptr<std::chrono::steady_clock::time_point> &deadline,
        std::string &request,
        Server::Config &cfg) {
    constexpr size_t MAX_REQUEST_SIZE = 1024 * 4;
    char buffer[MAX_REQUEST_SIZE];
    TrojanRequest req;
    for (;;) {
        *deadline = std::chrono::steady_clock::now() + cfg.read_write_max_idle;
        auto [ec, length] = co_await socket->async_read_some(
            asio::buffer(buffer, sizeof(buffer)),
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            spdlog::error("async_read_some: {}", ec.message());
            co_return std::unexpected(ParseError::NetworkError);
        }
        request.append(buffer, length);
        if (request.size() >= 58 && !std::ranges::equal(request.begin(),
                                                        request.begin() + 56,
                                                        cfg.passwd.begin(),
                                                        cfg.passwd.end())) {
            spdlog::error("invalid password: [{}]",
                          std::string{request.begin(), request.begin() + 56});
            co_await http301(socket);
            co_return std::unexpected(ParseError::PasswordError);
        }
        if (req.parse(request) != -1) {
            break;
        }
        if (request.size() > MAX_REQUEST_SIZE) {
            spdlog::error("request size too large: {}", request.size());
            co_await http301(socket);
            co_return std::unexpected(ParseError::PasswordError);
        }
    }
    co_return req;
}

asio::awaitable<std::optional<
    std::vector<asio::ip::tcp::resolver::results_type::value_type>>>
Server::resolve(const TrojanRequest &req) {
    std::vector<asio::ip::tcp::resolver::results_type::value_type> results;

    auto async_resolve = [](auto &req)
        -> asio::awaitable<std::optional<
            std::vector<asio::ip::tcp::resolver::results_type::value_type>>> {
        auto solver =
            asio::ip::tcp::resolver(co_await asio::this_coro::executor);
        auto [ec, results] =
            co_await solver.async_resolve(req.address.address,
                                          std::to_string(req.address.port),
                                          asio::as_tuple(asio::use_awaitable));
        if (ec) {
            spdlog::error("resolve [{}]: {}",
                          req.address.address,
                          ec.message());
            co_return std::nullopt;
        }

        std::vector<asio::ip::tcp::resolver::results_type::value_type>
            ipv4_entries;
        std::vector<asio::ip::tcp::resolver::results_type::value_type>
            ipv6_entries;

        for (const auto &entry : results) {
            if (entry.endpoint().address().is_v4()) {
                ipv4_entries.push_back(entry);
            } else {
                ipv6_entries.push_back(entry);
            }
        }
        if (ipv4_entries.empty()) {
            spdlog::info("ipv4_entries: {} ipv6_entries: {}",
                         ipv4_entries.size(),
                         ipv6_entries.size());
        }

        std::vector<asio::ip::tcp::resolver::results_type::value_type>
            prioritized_entries;

        prioritized_entries.insert(prioritized_entries.end(),
                                   ipv4_entries.begin(),
                                   ipv4_entries.end());
        prioritized_entries.insert(prioritized_entries.end(),
                                   ipv6_entries.begin(),
                                   ipv6_entries.end());

        co_return prioritized_entries;
    };

    std::unique_lock<std::mutex> lock(m_mtx);
    if (m_results.contains(req.address.address)) {
        results = m_results[req.address.address].results;
        lock.unlock();
    } else {
        lock.unlock();
        auto opt = co_await async_resolve(req);
        if (!opt.has_value()) {
            co_return std::nullopt;
        }
        std::unique_lock<std::mutex> lock(m_mtx);
        results = opt.value();
        m_results[req.address.address] = CachedResult{
            .results = std::move(opt.value()),
        };
    }
    co_return results;
}

void Server::stop() {
    auto ctx = m_io_ctx_pool->getMainContext();
    std::promise<void> done;
    asio::post(*ctx, [&] {
        if (m_acceptor)
            m_acceptor->close();
        done.set_value();
    });
    done.get_future().wait();
    m_io_ctx_pool->stop();
}

asio::awaitable<void> Server::session(
    std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket) {
    ScopeExit ssl_auto_exit([&socket] {
        asio::co_spawn(
            socket->get_executor(),
            [](auto socket) -> asio::awaitable<void> {
                co_await socket->async_shutdown(
                    asio::as_tuple(asio::use_awaitable));
            }(socket),
            asio::detached);
    });
    auto time_point = std::make_shared<std::chrono::steady_clock::time_point>(
        std::chrono::steady_clock::now());
    TrojanRequest req;
    {
        beast::flat_buffer buffer;
        http::parser<true, http::empty_body> parser;
        auto result = co_await (
            http::async_read_header(
                *socket, buffer, parser, asio::as_tuple(asio::use_awaitable)) ||
            timeout(m_cfg.timeout));
        if (result.index() == 1) {
            spdlog::error("async_read_header timeout");
            co_return;
        }
        auto [ec, bytes] = std::get<0>(result);
        if (ec == http::error::end_of_stream) {
            co_return;
        }
        if (ec == http::error::bad_method) {
            // 原始协议
            auto req_str = beast::buffers_to_string(buffer.data());
            if (req.parse(req_str) != -1) {
                if (req.password != m_cfg.passwd) {
                    spdlog::error("password error: {}", req.password);
                    co_await http301(socket);
                    co_return;
                }
            } else {
                auto result =
                    co_await (recvRequest(socket, time_point, req_str, m_cfg) ||
                              watchdog(time_point));
                if (result.index() == 1) {
                    spdlog::error("recvRequest timeout");
                    co_return;
                }
                auto &exception_req = std::get<0>(result);
                if (!exception_req.has_value()) {
                    co_return;
                }
                req = std::move(exception_req.value());
            }
        } else if (ec) {
            spdlog::error("{}", ec.message());
            co_await http301(socket);
            co_return;
        } else {
            auto &headers = parser.get();
            if (m_cfg.path != headers.target()) {
                spdlog::error("not expected path: {}", headers.target().data());
                co_await http301(socket);
                co_return;
            }

            http::response<http::empty_body> res{http::status::ok, 11};
            res.set(http::field::server, "nginx/1.20.1");
            res.keep_alive(true);
            auto [ec, bytes] =
                co_await http::async_write(*socket,
                                           res,
                                           asio::as_tuple(asio::use_awaitable));
            if (ec) {
                spdlog::error("http write error: {}", ec.message());
                co_return;
            }

            std::string req_str;
            auto result =
                co_await (recvRequest(socket, time_point, req_str, m_cfg) ||
                          watchdog(time_point));
            if (result.index() == 1) {
                spdlog::error("recvRequest timeout");
                co_return;
            }
            auto &exception_req = std::get<0>(result);
            if (!exception_req.has_value()) {
                co_return;
            }
            req = std::move(exception_req.value());
        }
    }
    if (req.command == TrojanRequest::Command::CONNECT) {
        auto out_socket = std::make_shared<asio::ip::tcp::socket>(
            co_await asio::this_coro::executor);

        ScopeExit auto_exit([&out_socket] {
            if (!out_socket->is_open()) {
                return;
            }
            boost::system::error_code ec;
            out_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both,
                                 ec);
            out_socket->close(ec);
        });

        auto results_opt = co_await resolve(req);
        if (!results_opt.has_value()) {
            co_return;
        }
        auto &results = results_opt.value();

        auto start = getCurrentTimestampMs();
        auto result = co_await (
            asio::async_connect(*out_socket,
                                results,
                                asio::as_tuple(asio::use_awaitable)) ||
            timeout(m_cfg.timeout));
        if (result.index() == 0) {
            auto [ec, ret] = std::get<0>(result);
            if (ec) {
                spdlog::error("connect: {}", ec.message());
                {
                    std::unique_lock<std::mutex> lock(m_mtx);
                    m_results.erase(req.address.address);
                }
                co_return;
            }
        } else if (result.index() == 1) {
            spdlog::error("connect timeout: {}", req.address.address);
            {
                std::unique_lock<std::mutex> lock(m_mtx);
                m_results.erase(req.address.address);
            }
            co_return;
        }
        auto end = getCurrentTimestampMs();
        if (end - start > 60) {
            spdlog::info("req.address.address: {}:{} -> {}",
                         req.address.address,
                         req.address.port,
                         end - start);
        }

        if (!req.payload.empty()) {
            if (auto [ec, len] = co_await asio::async_write(
                    *out_socket,
                    asio::buffer(req.payload.data(), req.payload.size()),
                    asio::as_tuple(asio::use_awaitable));
                ec) {
                spdlog::error("async_write: {}", ec.message());
                co_return;
            }
        }

        co_await (forward(socket, out_socket, time_point, m_cfg) ||
                  forward(out_socket, socket, time_point, m_cfg) ||
                  watchdog(time_point));

    } else {
        auto recv_udp = [](auto self,
                           auto payload,
                           auto socket,
                           auto deadline) -> asio::awaitable<void> {
            std::unordered_map<
                std::string,
                std::pair<asio::ip::udp::endpoint,
                          std::shared_ptr<asio::ip::udp::socket>>>
                udp_map;
            ScopeExit udp_auto_exit([&udp_map] {
                for (auto &[addr, data] : udp_map) {
                    auto &[endpoint, udp_socket] = data;
                    if (udp_socket->is_open()) {
                        boost::system::error_code ec;
                        udp_socket->cancel(ec);
                        udp_socket->close(ec);
                    }
                }
            });
            for (;;) {
                *deadline = std::chrono::steady_clock::now() +
                            self->m_cfg.read_write_max_idle;
                UdpPacket packet;
                size_t packet_len;
                bool is_packet_valid = packet.parse(payload, packet_len);
                if (!is_packet_valid) {
                    char buff[4096];
                    auto [ec, length] = co_await socket->async_read_some(
                        asio::buffer(buff, sizeof(buff)),
                        asio::as_tuple(asio::use_awaitable));
                    if (ec) {
                        break;
                    }
                    payload.append(buff, length);
                    if (payload.length() > 1024 * 8) {
                        co_await http301(socket);
                        break;
                    }
                } else {
                    payload = payload.substr(packet_len);
                    spdlog::debug("query_addr: [{}]", packet.address.address);
                    auto udp_to_tcp =
                        [](auto tcp_socket,
                           auto udp_socket,
                           auto deadline,
                           auto max_idle) -> asio::awaitable<void> {
                        asio::ip::udp::endpoint udp_recv_endpoint;
                        char buff[4096];
                        for (;;) {
                            *deadline =
                                std::chrono::steady_clock::now() + max_idle;
                            auto [ec, len] =
                                co_await udp_socket->async_receive_from(
                                    asio::buffer(buff, sizeof(buff)),
                                    udp_recv_endpoint,
                                    asio::as_tuple(asio::use_awaitable));
                            if (ec) {
                                // TROJAN_INFO_LOG("async_receive_from: {}",
                                // ec.message());
                                break;
                            }
                            auto data =
                                UdpPacket::generate(udp_recv_endpoint,
                                                    std::string(buff, len));
                            if (auto [ec, len] = co_await asio::async_write(
                                    *tcp_socket,
                                    asio::buffer(data),
                                    asio::as_tuple(asio::use_awaitable));
                                ec) {
                                spdlog::error("{}", ec.message());
                                break;
                            }
                        }
                    };
                    if (!udp_map.contains(packet.address.address)) {
                        asio::ip::udp::resolver udp_resolver(
                            co_await asio::this_coro::executor);
                        auto [err, results] =
                            co_await udp_resolver.async_resolve(
                                packet.address.address,
                                std::to_string(packet.address.port),
                                asio::as_tuple(asio::use_awaitable));
                        if (err || results.empty()) {
                            spdlog::error("resolve error: {}", err.message());
                            break;
                        }
                        for (const auto &entry : results) {
                            auto udp_socket =
                                std::make_shared<asio::ip::udp::socket>(
                                    co_await asio::this_coro::executor);
                            auto protocol = entry.endpoint().protocol();
                            boost::system::error_code ec;
                            udp_socket->open(protocol, ec);
                            if (ec) {
                                spdlog::error("open: {}", ec.message());
                                co_return;
                            }
                            udp_socket->bind(asio::ip::udp::endpoint(protocol,
                                                                     0),
                                             ec);
                            if (ec) {
                                spdlog::error("bind: {}", ec.message());
                                co_return;
                            }
                            udp_map[packet.address.address] =
                                std::make_pair(entry.endpoint(), udp_socket);
                            asio::co_spawn(
                                co_await asio::this_coro::executor,
                                udp_to_tcp(socket,
                                           udp_socket,
                                           deadline,
                                           self->m_cfg.read_write_max_idle),
                                asio::detached);
                            break;
                        }
                    }
                    auto &[endpoint, udp_socket] =
                        udp_map[packet.address.address];
                    auto [ec, len] = co_await udp_socket->async_send_to(
                        boost::asio::buffer(packet.payload.c_str(),
                                            packet.payload.size()),
                        endpoint,
                        asio::as_tuple(asio::use_awaitable));
                    if (ec) {
                        spdlog::error("async_send_to: {}", ec.message());
                        break;
                    }
                }
            }
        };

        auto deadline = std::make_shared<std::chrono::steady_clock::time_point>(
            std::chrono::steady_clock::now());
        co_await (recv_udp(this, std::move(req.payload), socket, deadline) ||
                  watchdog(deadline));
    }
    co_return;
}

}  // namespace trojan