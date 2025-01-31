module;

#include <cstdint>

export module var;

import std;
import boost;

export constexpr auto use_nothrow_awaitable =
    asio::as_tuple(asio::use_awaitable);
export constexpr std::size_t BUFFER_SIZE = 1024 * 10;
export constexpr int32_t MAX_LEN = 1024 * 8;
