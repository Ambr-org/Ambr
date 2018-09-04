CUR_DIR=.

ARCH_DIR=${CUR_DIR}/arch/linux
SERVER_DIR=${CUR_DIR}/src/server
MAIN_DIR=${CUR_DIR}/src
CRYPTO_DIR=${CUR_DIR}/src/crypto
LIB_DIR=${CUR_DIR}/libs
CROW_DIR=${CUR_DIR}/libs/crow
BLAKE2_DIR=${CUR_DIR}/libs/blake2
ARGON2_DIR=${CUR_DIR}/libs/argon2
ROCKSDB_DIR=${CUR_DIR}/libs/rocksdb
CRYPTOPP_DIR=${CUR_DIR}/libs/cryptopp
EDDONNA_DIR=${CUR_DIR}/libs/ed25519-donna
SYN_DIR=${CUR_DIR}/src/synchronization
CORE_DIR=${MAIN_DIR}/core
STORE_DIR=${MAIN_DIR}/store
P2P_DIR=${CUR_DIR}/src/p2p
RPC_DIR=${CUR_DIR}/src/rpc
PROTO_DIR=${CUR_DIR}/src/proto
RPC_LIB_DIR=${CUR_DIR}/libs/grpc
PROTOBUF_DIR=${RPC_LIB_DIR}/third_party/protobuf/src
GLOG_DIR=${CUR_DIR}/libs/glog

INC_DIR= -I${ARCH_DIR} \
         -I${MAIN_DIR} \
         -I${BLAKE2_DIR} \
         -I${ARGON2_DIR} \
         -I${EDDONNA_DIR} \
         -I${CRYPTOPP_DIR} \
         -I${CROW_DIR}/include \
         -I${ROCKSDB_DIR}/include \
         -I${LIB_DIR} \
	   -I${P2P_DIR} \
         -I${SYN_DIR} \
	   -I${RPC_LIB_DIR} \
	   -I${PROTOBUF_DIR} \
	   -I${GLOG_DIR}/src \
	   -I${RPC_LIB_DIR}/include 

SRC = ${wildcard  ${ARCH_DIR}/*.cc} \
      ${wildcard  ${SERVER_DIR}/*.cc} \
      ${wildcard  ${LIB_DIR}/*.cc} \
      ${wildcard  ${MAIN_DIR}/*.cc} \
      ${wildcard  ${CORE_DIR}/*.cc} \
      ${wildcard  ${CRYPTO_DIR}/blake2/*.cc} \
      ${wildcard  ${STORE_DIR}/*.cc} \
      ${wildcard  ${P2P_DIR}/*.cc} \
      ${wildcard  ${SYN_DIR}/*.cc} \
      ${wildcard  ${P2P_DIR}/compat/*.cc} \
      ${wildcard  ${P2P_DIR}/crypto/*.cc} \
      ${wildcard  ${P2P_DIR}/support/*.cc} \
      ${wildcard  ${RPC_DIR}/*.cc} \
      ${wildcard  ${PROTO_DIR}/*.cc} 


SRC_C = ${wildcard  ${BLAKE2_DIR}/*.c} \
        ${wildcard  ${EDDONNA_DIR}/ed25519.c} 

SRC_CPP = ${wildcard  ${CRYPTOPP_DIR}/*.cpp}

OBJ = ${patsubst %.cc, %.o, ${SRC}}
OBJC = ${patsubst %.c, %.o, ${SRC_C}}
OBJCPP = ${patsubst %.cpp, %.o, ${SRC_CPP}}

TARGET=ambr
CC=g++
CCFLAGS=-g -std=c++14 -Wall -Wreturn-type ${INC_DIR} 
CFLAGS=-g -Wall -Wreturn-type ${INC_DIR}




${TARGET}: ${OBJ} ${OBJC} ${OBJCPP}
	${CC} ${OBJ} ${OBJC} ${OBJCPP} -o $@ -L${ROCKSDB_DIR} -L${GLOG_DIR}/.libs -L${RPC_LIB_DIR}/libs/opt -L${RPC_LIB_DIR}/libs/opt/protobuf -lglog -lboost_system -pthread -lboost_program_options -lboost_thread -lboost_filesystem -lboost_chrono -lssl -lcrypto -lrocksdb -lprotobuf -lgrpc -lgpr -lgrpc++  -Wl,-rpath=${ROCKSDB_DIR}:${GLOG_DIR}/.libs:${RPC_LIB_DIR}/libs/opt
	@echo "Compile done."


$(OBJ):%.o:%.cc
	@echo "Compiling $< ==> $@"
	${CC} ${CCFLAGS} -c $< -o $@

$(OBJC):%.o:%.c
	@echo "Compiling $< ==> $@"
	${CC} ${CFLAGS} -c $< -o $@

$(OBJCPP):%.o:%.cpp
	@echo "Compiling $< ==> $@"
	${CC} ${CFLAGS} -c $< -o $@

clean:
	@rm -f ${OBJ}
	@rm -f ${OBJC}
	@rm -f ${OBJCPP}
	@echo "Clean object files done."

	@rm -f *~
	@echo "Clean tempreator files done."

	@rm -f ${TARGET}
	@echo "Clean target files done."

	@echo "Clean done."
