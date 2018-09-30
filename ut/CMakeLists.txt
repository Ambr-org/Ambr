cmake_minimum_required(VERSION 3.5.1)
project(test_case)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CUR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)

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
aux_source_directory(${CUR_DIR}/src/proto DIR_PROTO_SRCS)
aux_source_directory(${CUR_DIR}/src/synchronization DIR_SYNC_SRCS)
aux_source_directory(${CUR_DIR}/src/rpc DIR_RPC_SRCS)
aux_source_directory(${CUR_DIR}/ut/cases DIR_UT_SRCS)


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
set(UT_DIR ${CUR_DIR}/ut)
set(PROTOBUF_DIR ${CUR_DIR}/libs/grpc/third_party/protobuf)
set(RPC_LIB_DIR ${CUR_DIR}/libs/grpc)

include_directories(${MAIN_DIR})
include_directories(${CROW_DIR}/include)
include_directories(${LEVELDB_DIR}/include)
include_directories(${LIB_DIR})
include_directories(${ARCH_DIR})
include_directories(${ROCKSDB_DIR}/include)
include_directories(${GLOG_DIR}/src)
include_directories(${P2P_DIR})
include_directories(${UT_DIR}/googletest/googletest/include)
include_directories(${UT_DIR}/googletest/googlemock/include)
include_directories(${PROTOBUF_DIR}/src)


link_directories(${ROCKSDB_DIR})
link_directories(${GLOG_DIR}/.libs)
link_directories(${UT_DIR}/googletest/googletest)
link_directories(${UT_DIR}/googletest/googlemock)
link_directories(${RPC_LIB_DIR}/libs/opt/protobuf)
include_directories(${RPC_LIB_DIR}/include)
include_directories(${RPC_LIB_DIR}/third_party/protobuf/src)

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
link_libraries(gtest)
link_libraries(gmock)
link_libraries(protobuf)
link_libraries(protoc)
link_libraries(grpc++)
SET(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_FLAGS "-std=c++14 -Wall")
set(CMAKE_CXX_FLAGS "-Wall")


set(PROTO_SRC
  ${CUR_DIR}/src/proto/unit.pb.h
  ${CUR_DIR}/src/proto/unit.pb.cc
  )


add_custom_command(OUTPUT ${CUR_DIR}/src/proto/unit.pb.cc ${CUR_DIR}/src/proto/unit.pb.h
  COMMAND ../../libs/grpc/bins/opt/protobuf/protoc  --cpp_out=. unit.proto
  WORKING_DIRECTORY ${CUR_DIR}/src/proto/
  DEPENDS ${CUR_DIR}/src/proto/unit.proto)

add_executable(test_case
    ${PROTO_SRC}
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
    ${DIR_PROTO_SRCS}
    ${DIR_PROTO_HDRS}
    ${DIR_SYNC_SRCS}
    ${CUR_DIR}/libs/ed25519-donna/ed25519.c
    ${DIR_UT_SRCS}
    ${DIR_RPC_SRCS})



