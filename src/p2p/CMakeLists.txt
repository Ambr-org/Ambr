cmake_minimum_required(VERSION 3.5.1)

project(P2P)
 
set (dirs ${CMAKE_CURRENT_SOURCE_DIR} consensus crypto compat support) 

foreach(dir ${dirs})
  include_directories(${dir})
  file (GLOB sourcefiles RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${dir}/*.cc ${dir}/*.c ${dir}/*.h)
  list (APPEND sources ${sourcefiles})     
endforeach(dir ${dirs})
     

list (APPEND platform_libs pthread ssl crypto)
add_compile_options(-g -O0)
#find boost 
set(Boost_USE_STATIC_LIBS ON)
find_package (Boost 1.6.0 REQUIRED COMPONENTS date_time filesystem system log log_setup thread program_options regex chrono atomic)
include_directories (${Boost_INCLUDE_DIR})
list (APPEND platform_libs ${Boost_ATOMIC_LIBRARY} ${Boost_CHRONO_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_DATE_TIME_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LOG_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_LOG_SETUP_LIBRARY} ${Boost_THREAD_LIBRARY})

add_executable(p2p ${sources})
target_link_libraries(p2p ${platform_libs})

