#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <BS_thread_pool.hpp>
#include <spdlog/spdlog.h>

template <typename T>
class DnsResolver final {
  public:
    using Callback = std::function<void(std::vector<T>)>;

    DnsResolver(std::shared_ptr<BS::thread_pool<>> pool,
                std::shared_ptr<boost::asio::io_context> ctx)
        : m_pool(std::move(pool)), m_ctx(std::move(ctx)) {
        m_timer = std::make_unique<boost::asio::steady_timer>(*m_ctx);
        boost::asio::co_spawn(*m_ctx, dns(), boost::asio::detached);
    }

    ~DnsResolver() {
        m_timer->cancel();
    }

    boost::asio::awaitable<void> dns() {
        for (;;) {
            m_timer->expires_after(std::chrono::minutes(2));
            auto [ec] = co_await m_timer->async_wait(
                boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec) {
                break;
            }
            std::unique_lock<std::mutex> l(m_mtx);
            std::erase_if(m_results, [&](auto& p) {
                auto& [addr, cached_result] = p;
                return std::chrono::steady_clock::now() -
                           cached_result.expire_time >
                       std::chrono::minutes(60);
            });
            l.unlock();
        }
    }

    void resolve(const std::string& address,
                 const std::string& port,
                 Callback callback) {
        std::unique_lock<std::mutex> lock(m_mtx);
        if (m_results.contains(address)) {
            auto ret = m_results[address].results;
            lock.unlock();
            // SPDLOG_INFO("resolve [{}]: {} from cache", address, ret.size());
            callback(std::move(ret));
            return;
        }
        lock.unlock();
        m_pool->detach_task(
            [this, address, port, callback = std::move(callback)] {
                auto resolve_parse = [&](auto& solver) {
                    std::vector<T> prioritized_entries;
                    boost::system::error_code ec;
                    auto results = solver.resolve(address, port, ec);
                    if (ec) {
                        SPDLOG_ERROR("resolve [{}]: {}", address, ec.message());
                        callback(std::move(prioritized_entries));
                        return;
                    }

                    std::vector<T> ipv4_entries;
                    std::vector<T> ipv6_entries;

                    for (const auto& entry : results) {
                        if (entry.endpoint().address().is_v4()) {
                            ipv4_entries.push_back(entry);
                        } else {
                            ipv6_entries.push_back(entry);
                        }
                    }
                    if (ipv4_entries.empty()) {
                        SPDLOG_INFO("tcp ipv4_entries: {} ipv6_entries: {}",
                                    ipv4_entries.size(),
                                    ipv6_entries.size());
                    }

                    prioritized_entries.insert(prioritized_entries.end(),
                                               ipv4_entries.begin(),
                                               ipv4_entries.end());
                    prioritized_entries.insert(prioritized_entries.end(),
                                               ipv6_entries.begin(),
                                               ipv6_entries.end());
                    if (!prioritized_entries.empty()) {
                        std::unique_lock<std::mutex> lock(m_mtx);
                        m_results[address] = CachedResult{
                            .results = prioritized_entries,
                        };
                    }
                    callback(std::move(prioritized_entries));
                };
                if constexpr (std::is_same_v<T,
                                             boost::asio::ip::tcp::resolver::
                                                 results_type::value_type>) {
                    auto solver = boost::asio::ip::tcp::resolver(*m_ctx);
                    resolve_parse(solver);
                } else {
                    auto solver = boost::asio::ip::udp::resolver(*m_ctx);
                    resolve_parse(solver);
                }
                return;
            });
    }

    template <
        boost::asio::completion_token_for<void(std::vector<T>)> CompletionToken>
    auto async_resolve(const std::string& address,
                       const std::string& port,
                       CompletionToken&& token) {
        return boost::asio::async_initiate<CompletionToken,
                                           void(std::vector<T>)>(
            [this]<typename Handler>(Handler&& handler,
                                     const std::string& address,
                                     const std::string& port) mutable {
                auto handler_ptr =
                    std::make_shared<Handler>(std::forward<Handler>(handler));
                this->resolve(
                    address,
                    port,
                    [handler_ptr = std::move(handler_ptr)](
                        std::vector<T> results) mutable {
                        auto ex =
                            boost::asio::get_associated_executor(*handler_ptr);
                        boost::asio::post(
                            ex,
                            [handler_ptr = std::move(handler_ptr),
                             results = std::move(results)]() mutable -> void {
                                (*handler_ptr)(std::move(results));
                            });
                    });
            },
            std::forward<CompletionToken>(token),
            address,
            port);
    }

    void clear(const std::string& address) {
        std::unique_lock<std::mutex> lock(m_mtx);
        m_results.erase(address);
    }

  private:
    std::shared_ptr<BS::thread_pool<>> m_pool;
    std::shared_ptr<boost::asio::io_context> m_ctx;
    std::mutex m_mtx;
    std::unique_ptr<boost::asio::steady_timer> m_timer;

    struct CachedResult {
        std::vector<T> results;
        std::chrono::steady_clock::time_point expire_time{
            std::chrono::steady_clock::now()};
    };

    std::unordered_map<std::string, CachedResult> m_results;
};
