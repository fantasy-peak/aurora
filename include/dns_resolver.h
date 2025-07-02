#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <BS_thread_pool.hpp>

class DnsResolver final {
  public:
    using Callback = std::function<void(
        std::vector<boost::asio::ip::tcp::resolver::results_type::value_type>)>;

    using UdpCallback = std::function<void(
        std::vector<boost::asio::ip::udp::resolver::results_type::value_type>)>;

    DnsResolver(std::size_t pool_size = 4);
    ~DnsResolver() = default;

    void resolveTcp(const std::string& address,
                    const std::string& port,
                    Callback callback);

    void resolveUdp(const std::string& address,
                    const std::string& port,
                    UdpCallback callback);

    template <boost::asio::completion_token_for<void(
        std::vector<boost::asio::ip::tcp::resolver::results_type::value_type>)>
                  CompletionToken>
    auto resolve1(const std::string& address,
                  const std::string& port,
                  CompletionToken&& token) {
        return boost::asio::async_initiate<
            CompletionToken,
            void(std::vector<
                 boost::asio::ip::tcp::resolver::results_type::value_type>)>(
            [this]<typename Handler>(Handler&& handler,
                                     const std::string& address,
                                     const std::string& port) mutable {
                auto handler_ptr =
                    std::make_shared<Handler>(std::forward<Handler>(handler));
                this->resolveTcp(
                    address,
                    port,
                    [handler_ptr = std::move(handler_ptr)](
                        std::vector<boost::asio::ip::tcp::resolver::
                                        results_type::value_type>
                            results) mutable {
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

    template <boost::asio::completion_token_for<void(
        std::vector<boost::asio::ip::udp::resolver::results_type::value_type>)>
                  CompletionToken>
    auto resolve2(const std::string& address,
                  const std::string& port,
                  CompletionToken&& token) {
        return boost::asio::async_initiate<
            CompletionToken,
            void(std::vector<
                 boost::asio::ip::udp::resolver::results_type::value_type>)>(
            [this]<typename Handler>(Handler&& handler,
                                     const std::string& address,
                                     const std::string& port) mutable {
                auto handler_ptr =
                    std::make_shared<Handler>(std::forward<Handler>(handler));
                this->resolveUdp(
                    address,
                    port,
                    [handler_ptr = std::move(handler_ptr)](
                        std::vector<boost::asio::ip::udp::resolver::
                                        results_type::value_type>
                            results) mutable {
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

  private:
    std::unique_ptr<BS::thread_pool<>> m_pool;
    boost::asio::io_context m_ctx;
};
