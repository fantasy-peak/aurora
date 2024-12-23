import std;
import spdlog;
import Config;
import TrojanServer;
import TrojanClient;

int main(int, char** argv) {
    info(std::source_location::current(), "load: {}", argv[1]);
    auto cfg = loadConfig(argv[1]);

    switch (cfg.run_type) {
        case RunType::SERVER: {
            TrojanServer ts(cfg);
            ts.run();
            break;
        }
        case RunType::CLIENT: {
            TrojanClient tc(cfg);
            tc.run();
            break;
        }
    }

    return 0;
}
