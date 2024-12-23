module;

#include <cstdint>
#include <cstddef>

export module UdpPacket;

import std;
import boost;
import Socks5Address;

export class UdpPacket {
  public:
    Socks5Address address;
    uint16_t length;
    std::string payload;

    bool parse(const std::string &data, size_t &udp_packet_len) {
        if (data.length() <= 0) {
            return false;
        }
        size_t address_len;
        bool is_addr_valid = address.parse(data, address_len);
        if (!is_addr_valid || data.length() < address_len + 2) {
            return false;
        }
        length =
            (uint8_t(data[address_len]) << 8) | uint8_t(data[address_len + 1]);
        if (data.length() < address_len + 4 + length ||
            data.substr(address_len + 2, 2) != "\r\n") {
            return false;
        }
        payload = data.substr(address_len + 4, length);
        udp_packet_len = address_len + 4 + length;
        return true;
    }

    static std::string generate(const boost::asio::ip::udp::endpoint &endpoint,
                                const std::string &payload) {
        std::string ret = Socks5Address::generate(endpoint);
        ret += char(uint8_t(payload.length() >> 8));
        ret += char(uint8_t(payload.length() & 0xFF));
        ret += "\r\n";
        ret += payload;
        return ret;
    }

    static std::string generate(const std::string &domainname,
                                uint16_t port,
                                const std::string &payload) {
        std::string ret = "\x03";
        ret += char(uint8_t(domainname.length()));
        ret += domainname;
        ret += char(uint8_t(port >> 8));
        ret += char(uint8_t(port & 0xFF));
        ret += char(uint8_t(payload.length() >> 8));
        ret += char(uint8_t(payload.length() & 0xFF));
        ret += "\r\n";
        ret += payload;
        return ret;
    }
};
