CUR_DIR=../

ARCH_DIR=${CUR_DIR}/arch/linux
SERVER_DIR=${CUR_DIR}/src/server
MAIN_DIR=${CUR_DIR}/src
CRYPTO_DIR=${CUR_DIR}/src/crypto
LIB_DIR=${CUR_DIR}/libs
CROW_DIR=${CUR_DIR}/libs/crow
ARGON2_DIR=${CUR_DIR}/libs/argon2
LEVELDB_DIR=${CUR_DIR}/libs/leveldb
CRYPTOPP_DIR=${CUR_DIR}/libs/cryptopp
EDDONNA_DIR=${CUR_DIR}/libs/ed25519-donna
CORE_DIR=${MAIN_DIR}/core
STORE_DIR=${MAIN_DIR}/store
UT_DIR=${CUR_DIR}/ut/googletest
UT_CASE_DIR=${CUR_DIR}/ut/cases

INC_DIR= -I${ARCH_DIR} \
         -I${MAIN_DIR} \
				 -I${CRYPTO_DIR} \
				 -I${BLAKE2_DIR} \
				 -I${ARGON2_DIR} \
				 -I${EDDONNA_DIR} \
				 -I${CRYPTOPP_DIR} \
				 -I${CROW_DIR}/include \
				 -I${LEVELDB_DIR}/include \
         -I${LIB_DIR} \
		 		-I${UT_DIR}/googletest/include \
		 		-I${UT_DIR}/googlemock/include \
     
SRC = ${wildcard  ${ARCH_DIR}/*.cc} \
      ${wildcard  ${SERVER_DIR}/*.cc} \
      ${wildcard  ${LIB_DIR}/*.cc} \
      ${wildcard  ${CORE_DIR}/*.cc} \
      ${wildcard  ${UT_CASE_DIR}/*.cc} \
			${wildcard  ${CRYPTO_DIR}/blake2/*.cc} \
			${wildcard  ${STORE_DIR}/*.cc}
			

SRC_C = ${wildcard  ${EDDONNA_DIR}/ed25519.c} 

SRC_CPP = ${wildcard  ${CRYPTOPP_DIR}/*.cpp}

OBJ = ${patsubst %.cc, %.o, ${SRC}}
OBJC = ${patsubst %.c, %.o, ${SRC_C}}
OBJCPP = ${patsubst %.cpp, %.o, ${SRC_CPP}}

TARGET=ambr
CC=g++
CCFLAGS=-g -std=c++14 -Wall -Wreturn-type ${INC_DIR} 
CFLAGS=-g -Wall -Wreturn-type ${INC_DIR}
${TARGET}: ${OBJ} ${OBJC} ${OBJCPP}
	${CC} ${OBJ} ${OBJC} ${OBJCPP} -o $@ -L${LEVELDB_DIR} -L${UT_DIR}/googletest -L${UT_DIR}/googlemock -lboost_system -lleveldb -pthread -lboost_program_options -lssl -lcrypto -lgtest -lgmock
	@echo "Compile done."
	#./${TARGET}

#${OBJ}:${SRC}
#   $(CC) ${CCFLAGS} -c $? 

test:
	./${TARGET}

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