cmake_minimum_required(VERSION 3.18.4)

project(stan)

# You need to install flex and bison for libpcap to build
include(FetchContent)
FetchContent_Declare(
  pcap
  GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
  GIT_TAG        104271ba4a14de6743e43bcf87536786d8fddea4 # libpcap-1.10.4
)
FetchContent_MakeAvailable(pcap)
  
  
file(GLOB_RECURSE sources src/*.cpp src/*.hpp)
add_executable(stan stan.cpp ${sources})
target_link_libraries(stan pcap)
set_property(TARGET stan PROPERTY CXX_STANDARD 17)