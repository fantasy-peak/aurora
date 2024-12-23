module;

#include <sys/socket.h>
#include <netinet/tcp.h>

#include <openssl/ssl.h>
#include <spdlog/spdlog.h>
#include <boost/asio/require.hpp>

import std;
import boost;

export module Utils;

export inline boost::asio::awaitable<void> sleep(
    const std::chrono::seconds& duration) {
    auto now = std::chrono::steady_clock::now() + duration;
    boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor);
    timer.expires_at(now);
    [[maybe_unused]] auto [ec] = co_await timer.async_wait(
        boost::asio::as_tuple(boost::asio::use_awaitable));
    co_return;
}

export class ScopeExit {
  public:
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit(ScopeExit&&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    ScopeExit& operator=(ScopeExit&&) = delete;

    template <typename Callable>
    explicit ScopeExit(Callable&& call) : m_call(std::forward<Callable>(call)) {
    }

    ~ScopeExit() {
        if (m_call)
            m_call();
    }

    void clear() {
        m_call = decltype(m_call)();
    }

  private:
    std::function<void()> m_call;
};

export class IoContextPool final {
  public:
    explicit IoContextPool(std::size_t);

    void start();
    void stop();

    boost::asio::io_context& getIoContext();

  private:
    std::vector<std::shared_ptr<boost::asio::io_context>> m_io_contexts;
    std::list<boost::asio::any_io_executor> m_work;
    std::size_t m_next_io_context;
    std::vector<std::jthread> m_threads;
};

inline IoContextPool::IoContextPool(std::size_t pool_size)
    : m_next_io_context(0) {
    if (pool_size == 0)
        throw std::runtime_error("IoContextPool size is 0");
    for (std::size_t i = 0; i < pool_size; ++i) {
        auto io_context_ptr = std::make_shared<boost::asio::io_context>();
        m_io_contexts.emplace_back(io_context_ptr);
        m_work.emplace_back(boost::asio::require(
            io_context_ptr->get_executor(),
            boost::asio::execution::outstanding_work.tracked));
    }
}

inline void IoContextPool::start() {
    for (auto& context : m_io_contexts)
        m_threads.emplace_back(std::jthread([&] { context->run(); }));
}

inline void IoContextPool::stop() {
    for (auto& context_ptr : m_io_contexts)
        context_ptr->stop();
}

inline boost::asio::io_context& IoContextPool::getIoContext() {
    boost::asio::io_context& io_context = *m_io_contexts[m_next_io_context];
    ++m_next_io_context;
    if (m_next_io_context == m_io_contexts.size())
        m_next_io_context = 0;
    return io_context;
}

export inline void setsockopt(boost::asio::ip::tcp::socket& socket) {
    boost::system::error_code ec;
    socket.set_option(boost::asio::socket_base::keep_alive(true), ec);
    socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
    }

    auto sockfd = socket.native_handle();
#ifdef __linux__
    const int idle_time = 30;  // 单位: 秒
    if (setsockopt(
            sockfd, SOL_TCP, TCP_KEEPIDLE, &idle_time, sizeof(idle_time)) < 0) {
        std::cerr << "Error setting TCP_KEEPIDLE option\n";
    }
    // 设置 Keep-Alive 探测间隔时间
    const int keep_interval = 10;  // 单位: 秒
    if (setsockopt(sockfd,
                   SOL_TCP,
                   TCP_KEEPINTVL,
                   &keep_interval,
                   sizeof(keep_interval)) < 0) {
        std::cerr << "Error setting TCP_KEEPINTVL option\n";
    }
    // 设置最大 Keep-Alive 探测次数
    const int max_probe_count = 5;
    if (setsockopt(sockfd,
                   SOL_TCP,
                   TCP_KEEPCNT,
                   &max_probe_count,
                   sizeof(max_probe_count)) < 0) {
        std::cerr << "Error setting TCP_KEEPCNT option\n";
    }
#elif _WIN32
    // 设置 Keepalive 参数
    DWORD keep_alive_time = 20000;      // 空闲 20 秒后启动 Keepalive
    DWORD keep_alive_interval = 10000;  // 每 10 秒发送一个 Keepalive 包

    struct tcp_keepalive keep_alive;
    keep_alive.onoff = 1;                        // 启用 Keepalive
    keep_alive.keepalivetime = keep_alive_time;  // 启动 Keepalive 的时间
    keep_alive.keepaliveinterval = keep_alive_interval;  // Keepalive 之间的间隔

    DWORD dwBytes = 0L;
    // 设置 Keepalive 选项
    if (WSAIoctl(sockfd,
                 SIO_KEEPALIVE_VALS,
                 &keep_alive,
                 sizeof(keep_alive),
                 NULL,
                 0,
                 &dwBytes,
                 NULL,
                 NULL) == SOCKET_ERROR) {
        std::cerr << "Error setting TCP Keepalive parameters\n";
        return;
    }
#else
#endif
}

export inline boost::asio::awaitable<void> async_shutdown(auto socket) {
    auto [ec] = co_await socket->async_shutdown(
        boost::asio::as_tuple(boost::asio::use_awaitable));
    if (!socket->lowest_layer().is_open())
        co_return;
    socket->lowest_layer().cancel(ec);
    socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both,
                                    ec);
    socket->lowest_layer().close();
    co_return;
}

export inline std::string SHA224(const std::string& message) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    char mdString[(EVP_MAX_MD_SIZE << 1) + 1];
    unsigned int digest_len;
    EVP_MD_CTX* ctx;
    if ((ctx = EVP_MD_CTX_new()) == nullptr) {
        throw std::runtime_error("could not create hash context");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("could not initialize hash context");
    }
    if (!EVP_DigestUpdate(ctx, message.c_str(), message.length())) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("could not update hash");
    }
    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("could not output hash");
    }

    for (unsigned int i = 0; i < digest_len; ++i) {
        sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
    }
    mdString[digest_len << 1] = '\0';
    EVP_MD_CTX_free(ctx);
    return mdString;
}