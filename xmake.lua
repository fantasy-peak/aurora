add_rules("mode.release", "mode.debug")

set_project("aurora")

set_version("1.0.0", {build = "%Y%m%d%H%M"})
set_xmakever("2.9.6")

add_defines("BOOST_ASIO_HAS_IO_URING=1")
add_defines("BOOST_ASIO_DISABLE_EPOLL=1")

add_repositories("my_private_repo https://github.com/fantasy-peak/xmake-repo.git")

add_requires("liburing", {system = false})
add_requires("boost", {system = false, configs={cmake=false, url=true}})
add_requires("spdlog")
add_requires("nlohmann_json")
add_requires("openssl")

add_includedirs("include")

set_languages("c++23")

target("trojan-server")
    set_kind("binary")
    add_files("src/main.cpp",
        "src/ioctx_pool.cpp",
        "src/server.cpp")
    add_packages("boost", "spdlog", "nlohmann_json", "liburing", "openssl")
    add_ldflags("-static-libstdc++", "-static-libgcc", {force = true})
target_end()
