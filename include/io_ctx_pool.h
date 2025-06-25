#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include <cstddef>
#include <list>

#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio.hpp>

#include "utils.h"

namespace trojan {

class IoCtxPool final {
  public:
    IoCtxPool(std::size_t pool_size);
    ~IoCtxPool();

    void start();
    void stop();
    asio::io_context &getIoContext();
    std::shared_ptr<asio::io_context> &getIoContextPtr();
    std::shared_ptr<asio::io_context> &getMainContext();
    void createMainContext();

  private:
    void create();

    std::vector<std::shared_ptr<asio::io_context>> m_io_contexts;
    std::shared_ptr<asio::io_context> m_main_ioctx;
    std::list<asio::any_io_executor> m_work{};
    std::atomic_uint64_t m_next_io_context;
    std::vector<std::thread> m_threads;
    uint64_t m_pool_size;
};

}  // namespace trojan
