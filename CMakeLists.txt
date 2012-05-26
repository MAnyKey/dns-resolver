cmake_minimum_required(VERSION 2.6)

set(dns_resolver_cpps
  main.cpp
  resolver.cpp
  )

set(CMAKE_CXX_FLAGS "-Wall -Wextra -pedantic-errors -std=c++0x" ${CMAKE_CXX_FLAGS})
find_package(Boost COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
find_package(Threads)
add_executable(dns_resolver ${dns_resolver_cpps})
target_link_libraries(dns_resolver "${CMAKE_THREAD_LIBS_INIT}" "-lboost_system" "-lboost_program_options")