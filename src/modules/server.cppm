module;

export module TrojanServer;

import std;
import boost;
import Config;
import Utils;
import Network;

export class TrojanServer final {
  public:
    TrojanServer(const Config& config);

    asio::awaitable<void> session(
        std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket);
    void run();

  private:
    Config m_cfg;
    asio::ssl::context m_ssl_context;
    std::unique_ptr<Network> m_network;
};
