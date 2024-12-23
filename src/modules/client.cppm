module;

export module TrojanClient;

import std;
import boost;
import Config;
import Utils;
import Network;

export class TrojanClient final {
  public:
    TrojanClient(const Config& config);

    asio::awaitable<void> session(
        std::shared_ptr<asio::ip::tcp::socket> socket);
    void run();
    asio::awaitable<std::optional<std::shared_ptr<asio::ip::tcp::socket>>>
    createSocket(const std::string& target_ip, const std::string& target_port);

  private:
    Config m_cfg;
    asio::ssl::context m_ssl_context;
    std::string m_proxy_host;
    std::string m_proxy_port;
    std::unique_ptr<Network> m_network;
};
