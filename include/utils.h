#ifndef _UTILS_HPP_
#define _UTILS_HPP_

#include <functional>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <openssl/ssl.h>

namespace trojan {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

using namespace boost::asio::experimental::awaitable_operators;

class ScopeExit {
  public:
    ScopeExit(const ScopeExit &) = delete;
    ScopeExit(ScopeExit &&) = delete;
    ScopeExit &operator=(const ScopeExit &) = delete;
    ScopeExit &operator=(ScopeExit &&) = delete;

    template <typename Callable>
    explicit ScopeExit(Callable &&call) : m_call(std::forward<Callable>(call)) {
    }

    ~ScopeExit() {
        if (m_call)
            m_call();
    }

    void clear() {
        m_call = decltype(m_call)();
    }

  private:
    std::function<void()> m_call;
};

inline std::string SHA224(const std::string &message) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    char mdString[(EVP_MAX_MD_SIZE << 1) + 1];
    unsigned int digest_len;
    EVP_MD_CTX *ctx;
    if ((ctx = EVP_MD_CTX_new()) == nullptr) {
        throw std::runtime_error("could not create hash context");
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("could not initialize hash context");
    }
    if (!EVP_DigestUpdate(ctx, message.c_str(), message.length())) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("could not update hash");
    }
    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("could not output hash");
    }

    for (unsigned int i = 0; i < digest_len; ++i) {
        sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
    }
    mdString[digest_len << 1] = '\0';
    EVP_MD_CTX_free(ctx);
    return mdString;
}

}  // namespace trojan

#endif  // _UTILS_HPP_
