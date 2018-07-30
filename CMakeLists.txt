cmake_minimum_required(VERSION 3.5.1)
IF (CMAKE_SYSTEM_NAME MATCHES "Windows")
project(Ambr)
 
set (dirs src/core src/crypto src/server src/store src/utils src/wallet libs/blake2) 
set (sources src/main.cc libs/ed25519-donna/ed25519.c)
include_directories(src)
include_directories(libs)


foreach(dir ${dirs})
  include_directories(${dir})
  file (GLOB sourcefiles RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${dir}/*.cc ${dir}/*.c)
  list (APPEND sources ${sourcefiles})     
endforeach(dir ${dirs})

if (WIN32)
  LINK_DIRECTORIES (arch/windows/leveldb/debug/lib)
  LINK_DIRECTORIES (arch/windows/openssl/debug/lib)
  LINK_DIRECTORIES (arch/windows/crypto)
  include_directories(arch/windows/leveldb/include)
  include_directories(arch/windows/crow/include)
  include_directories(arch/windows/openssl/include())
  include_directories(arch/windows)
 
  list (APPEND platform_libs libleveldb shlwapi cryptlib libeay32 ssleay32)
else()
  include_directories(arch/linux)
  include_directories(libs/crow/include)
  list (APPEND platform_libs leveldb pthread ssl crypto)
endif()

#find boost 
set(Boost_USE_STATIC_LIBS ON)
find_package (Boost 1.6.0 REQUIRED COMPONENTS date_time filesystem system log log_setup thread program_options regex chrono atomic)
include_directories (${Boost_INCLUDE_DIR})
list (APPEND platform_libs ${Boost_ATOMIC_LIBRARY} ${Boost_CHRONO_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_DATE_TIME_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LOG_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_LOG_SETUP_LIBRARY} ${Boost_THREAD_LIBRARY})

add_executable(Ambr ${sources})
target_link_libraries(Ambr ${platform_libs})

#============================================
#example
#============================================
if (NOT WIN32)
add_subdirectory (libs/leveldb)
endif()

add_executable(example_uint examples/uint.cc)
add_executable(example_sha256 examples/sha256.cc)
add_executable(example_leveldb examples/leveldb.cc)
add_executable(example_unit examples/unit.cc src/core/unit.cc)

if(WIN32)
target_link_libraries (example_leveldb libleveldb shlwapi)

else()
set(CMAKE_CXX_FLAGS "-Wno-macro-redefined -std=c++14 -Wno-deprecated -Wno-error=return-type -Werror")
set(CMAKE_C_FLAGS "-Wno-macro-redefined -Wno-deprecated -Wno-error=return-type -Werror")
set_target_properties (example_uint example_sha256 example_leveldb example_unit PROPERTIES COMPILE_FLAGS "-std=c++14 -g")
set_target_properties (example_leveldb PROPERTIES LINK_FLAGS "-lpthread")
target_link_libraries (example_leveldb leveldb)
target_include_directories (example_uint PRIVATE src)
endif()
ELSE()
project(Ambr)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CUR_DIR .)

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(ARCH_DIR ${CUR_DIR}/arch/linux)
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(ARCH_DIR ${CUR_DIR}/arch/windows)
ELSE (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(ARCH_DIR ${CUR_DIR}/arch/mac)
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")

aux_source_directory(${ARCH_DIR} DIR_ARCH_SRCS)
aux_source_directory(${CUR_DIR}/src DIR_SRC_SRCS)
aux_source_directory(${CUR_DIR}/src/core DIR_CORE_SRCS)
aux_source_directory(${CUR_DIR}/src/crypto DIR_CRYPTO_SRCS)
aux_source_directory(${CUR_DIR}/src/net DIR_NET_SRCS)
aux_source_directory(${CUR_DIR}/src/server DIR_SERVER_SRCS)
aux_source_directory(${CUR_DIR}/src/store DIR_STORE_SRCS)
aux_source_directory(${CUR_DIR}/src/utils DIR_UTILS_SRCS)
aux_source_directory(${CUR_DIR}/src/wallet DIR_WALLET_SRCS)
aux_source_directory(${CUR_DIR}/src/crypto/blake2 DIR_BLAKE2_SRCS)
aux_source_directory(${CUR_DIR}/libs/cryptopp DIR_CRYPTOPP_SRCS)
#aux_source_directory(${CUR_DIR}/src/p2p DIR_P2P_SRCS)


set(SERVER_DIR ${CUR_DIR}/src/server)
set(MAIN_DIR ${CUR_DIR}/src)
set(LIB_DIR ${CUR_DIR}/libs)
set(CROW_DIR ${CUR_DIR}/libs/crow)
set(LEVELDB_DIR ${CUR_DIR}/libs/leveldb)
set(CORE_DIR ${CUR_DIR}/src/core)
set(ROCKSDB_DIR ${CUR_DIR}/libs/rocksdb)
set(GLOG_DIR ${CUR_DIR}/libs/glog)

include_directories(${MAIN_DIR})
include_directories(${CROW_DIR}/include)
include_directories(${LEVELDB_DIR}/include)
include_directories(${LIB_DIR})
include_directories(${ARCH_DIR})
include_directories(${ROCKSDB_DIR}/include)
include_directories(${GLOG_DIR}/src)

link_directories(${ROCKSDB_DIR})
link_directories(${GLOG_DIR}/.libs)

link_libraries(boost_system)
link_libraries(boost_thread)
link_libraries(boost_program_options)
link_libraries(pthread)
link_libraries(ssl)
link_libraries(crypto)
link_libraries(rocksdb)
link_libraries(glog)
SET(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_FLAGS "-std=c++14 -Wall")
set(CMAKE_CXX_FLAGS "-Wall")
add_executable(${PROJECT_NAME}
  ${DIR_ARCH_SRCS}
  ${DIR_SRC_SRCS}
  ${DIR_CORE_SRCS}
  ${DIR_NET_SRCS}
  ${DIR_SERVER_SRCS}
  ${DIR_STORE_SRCS}
  ${DIR_UTILS_SRCS}
  ${DIR_WALLET_SRCS}
  ${DIR_BLAKE2_SRCS}
  ${DIR_CRYPTOPP_SRCS}
  ${DIR_P2P_SRCS}
  ${CUR_DIR}/libs/ed25519-donna/ed25519.c
  )


set(GUI on)
if(DEFINED GUI)
  set(CMAKE_INCLUDE_CURRENT_DIR ON)
  set(CMAKE_AUTOMOC ON)
  set(CMAKE_AUTOUIC ON)
  set(CMAKE_AUTORCC ON)
  #set(RESOURCE_DIR resources/resources.qrc)

  find_package(Qt5 REQUIRED Widgets)
  qt5_wrap_cpp( MOC ${CUR_DIR}/examples/store_example_main_widget.h)
  qt5_wrap_ui( UIC ${CUR_DIR}/examples/store_example_main_widget.ui)
  #qt5_add_resources(RCC resources.qrc)
  set(QT_SRC
    ${CUR_DIR}/examples/store_example_main_widget.cc
    ${CUR_DIR}/examples/store_example_main_widget.h
    ${CUR_DIR}/examples/store_example_main_widget.ui)
  add_executable(unit_store_example
    ${DIR_ARCH_SRCS}
    ${DIR_CORE_SRCS}
    ${DIR_NET_SRCS}
    ${DIR_SERVER_SRCS}
    ${DIR_STORE_SRCS}
    ${DIR_UTILS_SRCS}
    ${DIR_WALLET_SRCS}
    ${DIR_BLAKE2_SRCS}
    ${DIR_CRYPTOPP_SRCS}
    ${CUR_DIR}/libs/ed25519-donna/ed25519.c
    examples/unit_store.cc
    examples/net_test.cc
    ${QT_SRC}
    )
  target_link_libraries(unit_store_example Qt5::Widgets)
else()
endif()

ENDIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
