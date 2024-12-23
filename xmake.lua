set_project("aurora")

set_version("1.0.0", {build = "%Y%m%d%H%M"})
set_xmakever("2.9.6")

add_defines("BOOST_ASIO_HAS_IO_URING=1")
add_defines("BOOST_ASIO_DISABLE_EPOLL=1")

add_repositories("my_private_repo https://github.com/fantasy-peak/xmake-repo.git")

add_requires("liburing", {system = false})
add_requires("boost", {system = false, configs={cmake=false, url=true}})
add_requires("spdlog", {configs={std_format=true}})
add_requires("nlohmann_json")

set_languages("c++26")
add_cxflags("-O3 -Wall -Wextra -pedantic-errors -Wno-missing-field-initializers -Wno-ignored-qualifiers")
set_policy("check.auto_ignore_flags", false)
set_policy("build.c++.modules", true)
set_policy("build.c++.modules.std", true)

target("aurora")
    set_kind("binary")
    add_files("src/modules/proto/udp_packet.cppm",
        "src/modules/proto/socks5_address.cppm",
        "src/modules/proto/trojan_request.cppm")
    add_files("src/modules/core/log.cppm",
        "src/modules/core/config.cppm",
        "src/modules/core/utils.cppm",
        "src/modules/core/boost.cppm",
        "src/modules/core/root.cppm",
        "src/modules/core/network.cppm", {public = true})
    add_files("src/modules/server.cppm",
        "src/modules/client.cppm", {public = true})
    add_files("src/main.cpp",
        "src/server_impl.cpp",
        "src/client_impl.cpp")
    add_links("ssl", "crypto")
    add_packages("boost", "spdlog", "nlohmann_json", "liburing")
target_end()
