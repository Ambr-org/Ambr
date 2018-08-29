cmake_minimum_required(VERSION 3.5.1)
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

find_package(Protobuf REQUIRED)
PROTOBUF_GENERATE_CPP(DIR_PROTO_SRCS DIR_PROTO_HDRS ${CUR_DIR}/src/proto/unit.proto)
#add_executable(${DIR_PROTO_SRCS} ${DIR_PROTO_HDRS})
#target_link_libraries(${PROTOBUF_LIBRARIES})

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
aux_source_directory(${CUR_DIR}/src/p2p DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/crypto  DIR_P2P_SRCS)
#aux_source_directory(${CUR_DIR}/src/p2p/crypto/ctaes DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/support DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/consensus DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/compat DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/proto DIR_PROTO_SRCS)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(SERVER_DIR ${CUR_DIR}/src/server)
set(MAIN_DIR ${CUR_DIR}/src)
set(LIB_DIR ${CUR_DIR}/libs)
set(CROW_DIR ${CUR_DIR}/libs/crow)
set(LEVELDB_DIR ${CUR_DIR}/libs/leveldb)
set(CORE_DIR ${CUR_DIR}/src/core)
set(ROCKSDB_DIR ${CUR_DIR}/libs/rocksdb)
set(GLOG_DIR ${CUR_DIR}/libs/glog)
set(P2P_DIR ${CUR_DIR}/src/p2p)
set(PROTOBUF_DIR ${CUR_DIR}/libs/protobuf)

include_directories(${MAIN_DIR})
include_directories(${CROW_DIR}/include)
include_directories(${LEVELDB_DIR}/include)
include_directories(${LIB_DIR})
include_directories(${ARCH_DIR})
include_directories(${ROCKSDB_DIR}/include)
include_directories(${GLOG_DIR}/src)
include_directories(${P2P_DIR})
INCLUDE_DIRECTORIES(${PROTOBUF_DIR}/src)

link_directories(${ROCKSDB_DIR})
link_directories(${GLOG_DIR}/.libs)
link_libraries(boost_chrono)
link_libraries(boost_filesystem)
link_libraries(boost_system)
link_libraries(boost_thread)
link_libraries(boost_program_options)
link_libraries(pthread)
link_libraries(ssl)
link_libraries(crypto)
link_libraries(rocksdb)
link_libraries(glog)
link_libraries(protobuf)
link_libraries(protoc)
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
  ${DIR_PROTO_SRCS}
  ${DIR_PROTO_HDRS}
  ${CUR_DIR}/libs/ed25519-donna/ed25519.c
  )


if(DEFINED EXAMPLE)
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
    ${DIR_PROTO_SRCS}
    ${CUR_DIR}/libs/ed25519-donna/ed25519.c
    examples/unit_store.cc
    examples/net_test.cc
    ${QT_SRC}
    )
  target_link_libraries(unit_store_example Qt5::Widgets)
else()
endif()
