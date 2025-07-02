#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <netdb.h>
#include <spdlog/spdlog.h>

#include "dns_resolver.h"

DnsResolver::DnsResolver(std::size_t pool_size) {
    m_pool = std::make_unique<BS::thread_pool<>>(pool_size);
}

void DnsResolver::resolveTcp(const std::string &address,
                             const std::string &port,
                             Callback callback) {
    m_pool->detach_task([this, address, port, callback = std::move(callback)] {
        std::vector<boost::asio::ip::tcp::resolver::results_type::value_type>
            prioritized_entries;

        auto solver = boost::asio::ip::tcp::resolver(m_ctx);
        boost::system::error_code ec;
        auto results = solver.resolve(address, port, ec);
        if (ec) {
            SPDLOG_ERROR("resolve [{}]: {}", address, ec.message());
            callback(std::move(prioritized_entries));
            return;
        }

        std::vector<boost::asio::ip::tcp::resolver::results_type::value_type>
            ipv4_entries;
        std::vector<boost::asio::ip::tcp::resolver::results_type::value_type>
            ipv6_entries;

        for (const auto &entry : results) {
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

        callback(std::move(prioritized_entries));
        return;
    });
}

void DnsResolver::resolveUdp(const std::string &address,
                             const std::string &port,
                             UdpCallback callback) {
    m_pool->detach_task([this, address, port, callback = std::move(callback)] {
        std::vector<boost::asio::ip::udp::resolver::results_type::value_type>
            prioritized_entries;

        auto solver = boost::asio::ip::udp::resolver(m_ctx);
        boost::system::error_code ec;
        auto results = solver.resolve(address, port, ec);
        if (ec) {
            SPDLOG_ERROR("resolve [{}]: {}", address, ec.message());
            callback(std::move(prioritized_entries));
            return;
        }

        std::vector<boost::asio::ip::udp::resolver::results_type::value_type>
            ipv4_entries;
        std::vector<boost::asio::ip::udp::resolver::results_type::value_type>
            ipv6_entries;

        for (const auto &entry : results) {
            if (entry.endpoint().address().is_v4()) {
                ipv4_entries.push_back(entry);
            } else {
                ipv6_entries.push_back(entry);
            }
        }
        if (ipv4_entries.empty()) {
            SPDLOG_INFO("udp ipv4_entries: {} ipv6_entries: {}",
                        ipv4_entries.size(),
                        ipv6_entries.size());
        }

        prioritized_entries.insert(prioritized_entries.end(),
                                   ipv4_entries.begin(),
                                   ipv4_entries.end());
        prioritized_entries.insert(prioritized_entries.end(),
                                   ipv6_entries.begin(),
                                   ipv6_entries.end());

        callback(std::move(prioritized_entries));
        return;
    });
}