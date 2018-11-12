cmake_minimum_required(VERSION 3.5.1)
project(unit_store_example)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CUR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

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
aux_source_directory(${CUR_DIR}/src/p2p DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/crypto  DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/support DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/consensus DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/p2p/compat DIR_P2P_SRCS)
aux_source_directory(${CUR_DIR}/src/synchronization DIR_SYN_SRCS)


set(SERVER_DIR ${CUR_DIR}/src/server)
set(MAIN_DIR ${CUR_DIR}/src)
set(LIB_DIR ${CUR_DIR}/libs)
set(CROW_DIR ${CUR_DIR}/libs/crow)
set(LEVELDB_DIR ${CUR_DIR}/libs/leveldb)
set(CORE_DIR ${CUR_DIR}/src/core)
set(ROCKSDB_DIR ${CUR_DIR}/libs/rocksdb)
set(GLOG_DIR ${CUR_DIR}/libs/glog)
set(P2P_DIR ${CUR_DIR}/src/p2p)
set(SYN_DIR ${CUR_DIR}/src/synchronizatio)
set(RPC_LIB_DIR ${CUR_DIR}/libs/grpc)
#set(PROTOBUF_DIR ${CUR_DIR}/libs/protobuf)

include_directories(${MAIN_DIR})
include_directories(${CROW_DIR}/include)
include_directories(${LEVELDB_DIR}/include)
include_directories(${LIB_DIR})
include_directories(${ARCH_DIR})
include_directories(${ROCKSDB_DIR}/include)
include_directories(${GLOG_DIR}/src)
include_directories(${P2P_DIR})
include_directories(${SYN_DIR})
include_directories(${RPC_LIB_DIR}/include)
include_directories(${RPC_LIB_DIR}/third_party/protobuf/src)

link_directories(${ROCKSDB_DIR})
link_directories(${GLOG_DIR}/.libs)
link_directories(${RPC_LIB_DIR}/libs/opt)
link_directories(${RPC_LIB_DIR}/libs/opt/protobuf)
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

SET(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_FLAGS "-std=c++14 -Wall")
set(CMAKE_CXX_FLAGS "-Wall")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt5 REQUIRED Widgets)
#qt5_wrap_cpp( MOC ${CUR_DIR}/examples/store_example_main_widget.h)
#qt5_wrap_ui( UIC ${CUR_DIR}/examples/store_example_main_widget.ui)
QT5_ADD_RESOURCES(RCC ${CUR_DIR}/examples/store_example_main_widget.qrc)
set(QT_SRC
  ${CUR_DIR}/examples/store_example_main_widget.cc
  ${CUR_DIR}/examples/store_example_main_widget.h
  ${CUR_DIR}/examples/store_example_main_widget.ui)


set(PROTO_SRC
  ${CUR_DIR}/src/proto/unit.pb.h
  ${CUR_DIR}/src/proto/unit.pb.cc
  )


add_custom_command(OUTPUT ${CUR_DIR}/src/proto/unit.pb.cc ${CUR_DIR}/src/proto/unit.pb.h
  COMMAND ${CUR_DIR}/libs/grpc/third_party/protobuf/src/.libs/protoc  --cpp_out=. unit.proto
  WORKING_DIRECTORY ${CUR_DIR}/src/proto/
  DEPENDS ${CUR_DIR}/src/proto/unit.proto)

set(RPC_SRC
  ${CUR_DIR}/src/rpc/rpc.grpc.pb.cc
  ${CUR_DIR}/src/rpc/rpc.grpc.pb.h
  ${CUR_DIR}/src/rpc/rpc.pb.cc
  ${CUR_DIR}/src/rpc/rpc.pb.h
  ${CUR_DIR}/src/rpc/rpc_server.cc
  ${CUR_DIR}/src/rpc/rpc_server.h
  )
add_custom_command(OUTPUT ${CUR_DIR}/src/rpc/rpc.grpc.pb.cc ${CUR_DIR}/src/rpc/rpc.grpc.pb.h
  COMMAND ${CUR_DIR}/libs/grpc/third_party/protobuf/src/.libs/protoc  --grpc_out=. --plugin=protoc-gen-grpc=${CUR_DIR}/libs/grpc/bins/opt/grpc_cpp_plugin rpc.proto
  WORKING_DIRECTORY ${CUR_DIR}/src/rpc/
  DEPENDS ${CUR_DIR}/src/rpc/rpc.proto)

add_custom_command(OUTPUT ${CUR_DIR}/src/rpc/rpc.pb.cc ${CUR_DIR}/src/rpc/rpc.pb.h
  COMMAND ${CUR_DIR}/libs/grpc/third_party/protobuf/src/.libs/protoc  --cpp_out=. rpc.proto
  WORKING_DIRECTORY ${CUR_DIR}/src/rpc/
  DEPENDS ${CUR_DIR}/src/rpc/rpc.proto)

set_property(SOURCE ${RPC_SRC} ${PROTO_SRC} PROPERTY SKIP_AUTOGEN ON)

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
  ${DIR_P2P_SRCS}
  ${DIR_SYN_SRCS}
  ${CUR_DIR}/libs/ed25519-donna/ed25519.c
  ${CUR_DIR}/examples/unit_store.cc
  ${QT_SRC}
  ${RPC_SRC}
  ${PROTO_SRC}
  ${RCC}
  ${DIR_PROTO_SRCS}
  ${DIR_PROTO_HDRS}
  )
target_link_libraries(unit_store_example Qt5::Widgets)
target_link_libraries(unit_store_example grpc++  protobuf)
