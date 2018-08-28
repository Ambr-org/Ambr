cmake_minimum_required(VERSION 3.5.1)
project(chat_example)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CUR_DIR ../..)

set(MAIN_DIR ${CUR_DIR}/src)



link_directories(${GLOG_DIR}/.libs)
include_directories(${MAIN_DIR})

SET(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_FLAGS "-std=c++14 -Wall")
set(CMAKE_CXX_FLAGS "-Wall")


set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)



find_package(Qt5 REQUIRED Widgets)
qt5_wrap_cpp( MOC ${CUR_DIR}/examples/ChatExample/main_widget.h)
qt5_wrap_ui( UIC ${CUR_DIR}/examples/ChatExample/main_widget.ui)
QT5_ADD_RESOURCES(RCC ${CUR_DIR}/examples/ChatExample/main_widget.qrc)
set(QT_SRC
  ${CUR_DIR}/examples/ChatExample/main_widget.cc
  ${CUR_DIR}/examples/ChatExample/main_widget.h
  ${CUR_DIR}/examples/ChatExample/main_widget.ui)

set(RPC_SRC
  ${CUR_DIR}/src/rpc/rpc.grpc.pb.cc
  ${CUR_DIR}/src/rpc/rpc.grpc.pb.h
  ${CUR_DIR}/src/rpc/rpc.pb.cc
  ${CUR_DIR}/src/rpc/rpc.pb.h
  )
add_custom_command(OUTPUT ${CUR_DIR}/src/rpc/rpc.grpc.pb.cc ${CUR_DIR}/src/rpc/rpc.grpc.pb.h
  COMMAND protoc  --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` rpc.proto
  WORKING_DIRECTORY ${CUR_DIR}/src/rpc/
  DEPENDS ${CUR_DIR}/src/rpc/rpc.proto)

add_custom_command(OUTPUT ${CUR_DIR}/src/rpc/rpc.pb.cc ${CUR_DIR}/src/rpc/rpc.pb.h
  COMMAND protoc  --cpp_out=. rpc.proto
  WORKING_DIRECTORY ${CUR_DIR}/src/rpc/
  DEPENDS ${CUR_DIR}/src/rpc/rpc.proto)

add_executable(chat_example
  ${QT_SRC}
  ${CUR_DIR}/examples/ChatExample/main.cc
  ${RPC_SRC}
  ${MOC}
  ${RCC}
  )


include_directories(${CUR_DIR}/src)
include_directories(${CUR_DIR}/libs)
ADD_LIBRARY (assist_lib SHARED
  ${CUR_DIR}/src/core/key.cc
  ${CUR_DIR}/src/core/unit.cc
  ${CUR_DIR}/src/crypto/blake2/blake2b.cc
  ${CUR_DIR}/libs/ed25519-donna/ed25519.c
  ${CUR_DIR}/examples/ChatExample/assist_lib.cc)

target_link_libraries(chat_example Qt5::Widgets)
target_link_libraries(chat_example grpc++  protobuf)
target_link_libraries(chat_example assist_lib)
