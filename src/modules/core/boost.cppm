module;

#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/detail/socket_option.hpp>
#include <boost/asio/ssl/error.hpp>

#include <boost/beast/http.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/core.hpp>

#include <boost/system/detail/error_code.hpp>

#include <boost/url.hpp>

export module boost;

import std;
import spdlog;

export namespace asio = boost::asio;
export using namespace boost::asio::experimental::awaitable_operators;
export namespace http = boost::beast::http;
export namespace beast = boost::beast;

export namespace boost::urls {
using boost::urls::url;
}

export namespace boost::asio {
using boost::asio::any_io_executor;
using boost::asio::as_tuple;
using boost::asio::async_read;
using boost::asio::async_read_until;
using boost::asio::async_write;
using boost::asio::awaitable;
using boost::asio::buffer;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::io_context;
using boost::asio::partial_as_tuple;
using boost::asio::post;
using boost::asio::socket_base;
using boost::asio::steady_timer;
using boost::asio::use_awaitable;
}  // namespace boost::asio

export namespace boost::asio::error {
using boost::asio::error::get_ssl_category;
}

export namespace boost::asio::experimental::awaitable_operators {
using boost::asio::experimental::awaitable_operators::operator&&;
using boost::asio::experimental::awaitable_operators::operator||;
}  // namespace boost::asio::experimental::awaitable_operators

export namespace boost::asio::ssl {
using boost::asio::ssl::context;
using boost::asio::ssl::stream;
using boost::asio::ssl::stream_base;
}  // namespace boost::asio::ssl

export namespace boost::asio::ip {
using boost::asio::ip::address;
using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using boost::asio::ip::operator<<;
}  // namespace boost::asio::ip

export namespace boost::asio::this_coro {
using boost::asio::this_coro::executor;
}  // namespace boost::asio::this_coro

export namespace boost::asio::execution {
using boost::asio::execution::outstanding_work;
}  // namespace boost::asio::execution

export namespace boost::system {
using boost::system::error_code;
}  // namespace boost::system

export namespace boost::asio::detail::socket_option {
using boost::asio::detail::socket_option::integer;
}

export namespace boost::beast {
using boost::beast::flat_buffer;
}

export namespace boost::beast::http {
using boost::beast::http::basic_fields;
using boost::beast::http::empty_body;
using boost::beast::http::field;
using boost::beast::http::message;
using boost::beast::http::request;
using boost::beast::http::response;
using boost::beast::http::status;
using boost::beast::http::string_body;
using boost::beast::http::verb;
using boost::beast::http::operator<<;
using boost::beast::http::async_read;
using boost::beast::http::async_write;
using boost::beast::http::parser;
}  // namespace boost::beast::http

export struct Http {
    static std::string createHttp301(
        const std::string& url = "https://www.baidu.com") {
        namespace http = boost::beast::http;
        http::response<http::empty_body> res{http::status::moved_permanently,
                                             11};
        res.set(http::field::location, url);
        res.set(http::field::server, "nginx/1.20.1");
        std::stringstream ss;
        ss << res;
        return ss.str();
    }

    static asio::awaitable<bool> connectHttpProxy(auto& target_ip,
                                 auto& target_port,
                                 auto& socket) {
        constexpr int http_version = 11;
        auto target = std::format("{}:{}", target_ip, target_port);
        http::request<http::string_body> connect_req{http::verb::connect,
                                                     target,
                                                     http_version};
        connect_req.set(http::field::host, target);
        connect_req.set(http::field::user_agent,
                        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0)
            Gecko/20100101 Firefox/133.0)");
        connect_req.set(http::field::proxy_connection, "keep-alive");
        connect_req.set(http::field::connection, "keep-alive");

        auto [ec, count] =
            co_await http::async_write(socket,
                                       connect_req,
                                       asio::as_tuple(asio::use_awaitable));
        if (ec) {
            error(std::source_location::current(), "{}", ec.message());
            co_return false;
        }
        http::response<http::empty_body> res;
        http::parser<false, http::empty_body> http_parser(res);
        http_parser.skip(true);

        boost::beast::flat_buffer buffer;
        std::tie(ec, count) = co_await http::async_read(
            socket, buffer, http_parser, asio::as_tuple(asio::use_awaitable));
        if (http::status::ok != res.result()) {
            error(std::source_location::current(),
                  "Proxy response failed : {}",
                  res.result_int());
            co_return false;
        }
        co_return true;
    }
};
