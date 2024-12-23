module;

#include <cstdint>
#include <cstddef>
#include <cstdio>

export module Socks5Address;

import std;
import boost;

export class Socks5Address {
  public:
    enum AddressType { IPv4 = 1, DOMAINNAME = 3, IPv6 = 4 } address_type;

    std::string address;
    uint16_t port;

    bool parse(const std::string &data, size_t &address_len) {
        if (data.length() == 0 ||
            (data[0] != IPv4 && data[0] != DOMAINNAME && data[0] != IPv6)) {
            return false;
        }
        address_type = static_cast<AddressType>(data[0]);
        switch (address_type) {
            case IPv4: {
                if (data.length() > 4 + 2) {
                    address = std::to_string(uint8_t(data[1])) + '.' +
                              std::to_string(uint8_t(data[2])) + '.' +
                              std::to_string(uint8_t(data[3])) + '.' +
                              std::to_string(uint8_t(data[4]));
                    port = (uint8_t(data[5]) << 8) | uint8_t(data[6]);
                    address_len = 1 + 4 + 2;
                    return true;
                }
                break;
            }
            case DOMAINNAME: {
                uint8_t domain_len = data[1];
                if (domain_len == 0) {
                    // invalid domain len
                    break;
                }
                if (data.length() > (unsigned int)(1 + domain_len + 2)) {
                    address = data.substr(2, domain_len);
                    port = (uint8_t(data[domain_len + 2]) << 8) |
                           uint8_t(data[domain_len + 3]);
                    address_len = 1 + 1 + domain_len + 2;
                    return true;
                }
                break;
            }
            case IPv6: {
                if (data.length() > 16 + 2) {
                    char t[40];
                    sprintf(
                        t,
                        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                        "%02x%02x:%02x%02x",
                        uint8_t(data[1]),
                        uint8_t(data[2]),
                        uint8_t(data[3]),
                        uint8_t(data[4]),
                        uint8_t(data[5]),
                        uint8_t(data[6]),
                        uint8_t(data[7]),
                        uint8_t(data[8]),
                        uint8_t(data[9]),
                        uint8_t(data[10]),
                        uint8_t(data[11]),
                        uint8_t(data[12]),
                        uint8_t(data[13]),
                        uint8_t(data[14]),
                        uint8_t(data[15]),
                        uint8_t(data[16]));
                    address = t;
                    port = (uint8_t(data[17]) << 8) | uint8_t(data[18]);
                    address_len = 1 + 16 + 2;
                    return true;
                }
                break;
            }
        }
        return false;
    }

    static std::string generate(
        const boost::asio::ip::udp::endpoint &endpoint) {
        if (endpoint.address().is_unspecified()) {
            return std::string("\x01\x00\x00\x00\x00\x00\x00", 7);
        }
        std::string ret;
        if (endpoint.address().is_v4()) {
            ret += '\x01';
            auto ip = endpoint.address().to_v4().to_bytes();
            for (int i = 0; i < 4; ++i) {
                ret += char(ip[i]);
            }
        }
        if (endpoint.address().is_v6()) {
            ret += '\x04';
            auto ip = endpoint.address().to_v6().to_bytes();
            for (int i = 0; i < 16; ++i) {
                ret += char(ip[i]);
            }
        }
        ret += char(uint8_t(endpoint.port() >> 8));
        ret += char(uint8_t(endpoint.port() & 0xFF));
        return ret;
    }
};
