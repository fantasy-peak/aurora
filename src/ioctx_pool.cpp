#include <stdexcept>

#include "ioctx_pool.h"

namespace trojan {

IoCtxPool::IoCtxPool(std::size_t pool_size)
    : m_next_io_context(0), m_pool_size(pool_size) {
    if (pool_size == 0)
        throw std::runtime_error("ContextPool size is 0");
    for (std::size_t i = 0; i < pool_size; ++i) {
        create();
    }
}

IoCtxPool::~IoCtxPool() {
    stop();
}

void IoCtxPool::start() {
    for (auto &context : m_io_contexts)
        m_threads.emplace_back([&] { context->run(); });
}

void IoCtxPool::stop() {
    for (auto &context_ptr : m_io_contexts)
        context_ptr->stop();
    for (auto &thread : m_threads) {
        if (thread.joinable())
            thread.join();
    }
}

asio::io_context &IoCtxPool::getIoContext() {
    size_t index = m_next_io_context.fetch_add(1, std::memory_order_relaxed);
    return *m_io_contexts[index % m_pool_size];
}

std::shared_ptr<asio::io_context> &IoCtxPool::getIoContextPtr() {
    size_t index = m_next_io_context.fetch_add(1, std::memory_order_relaxed);
    return m_io_contexts[index % m_pool_size];
}

std::shared_ptr<asio::io_context> &IoCtxPool::getMainContext() {
    return m_io_contexts.back();
}

void IoCtxPool::createMainContext() {
    create();
}

void IoCtxPool::create() {
    auto io_context_ptr = std::make_shared<asio::io_context>();
    m_io_contexts.emplace_back(io_context_ptr);
    m_work.emplace_back(
        asio::require(io_context_ptr->get_executor(),
                      asio::execution::outstanding_work.tracked));
}

}  // namespace trojan
