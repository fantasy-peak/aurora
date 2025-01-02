# aurora

xmake f --toolchain=llvm --runtimes=c++_static -c
xmake build -v -y --file=./xmake.lua
xmake project -k compile_commands
apt install clang-tools clang clang++ libc++-20-dev libc++-dev libc++abi-dev