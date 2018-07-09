CUR_DIR=../

ARCH_DIR=${CUR_DIR}/arch/linux
SERVER_DIR=${CUR_DIR}/src/server
CRYPTO_DIR=${CUR_DIR}/src/crypto
MAIN_DIR=${CUR_DIR}/src
LIB_DIR=${CUR_DIR}/libs
CROW_DIR=${CUR_DIR}/libs/crow
LEVELDB_DIR=${CUR_DIR}/libs/leveldb
UT_DIR=${CUR_DIR}/ut/googletest
UT_CASE_DIR=${CUR_DIR}/ut/cases

INC_DIR= -I${ARCH_DIR} \
         -I${MAIN_DIR} \
		 -I${CRYPTO_DIR} \
		 -I${SERVER_DIR} \
		 -I${CROW_DIR}/include \
		 -I${LEVELDB_DIR}/include \
         -I${LIB_DIR} \
		 -I${UT_DIR}/googletest/include \
		 -I${UT_DIR}/googlemock/include \

SRC = ${wildcard  ${ARCH_DIR}/*.cc} \
	  ${wildcard  ${SERVER_DIR}/*.cc} \
      ${wildcard  ${LIB_DIR}/*.cc} \
	  ${wildcard  ${UT_CASE_DIR}/*.cc} \

OBJ = ${patsubst %.cc, %.o, ${SRC}}

TARGET=ut_ambr
CC=g++
CCFLAGS=-g -std=c++14 -Wall ${INC_DIR} -pthread

#g++ ./arch/linux/platform.o  ./src/server/ambrd.o  ./src/main.o -o ambr -lboost_system -pthread
${TARGET}: ${OBJ}
	${CC} ${OBJ} -o $@ -L${LEVELDB_DIR} -L${UT_DIR}/googletest -L${UT_DIR}/googlemock -lboost_system -lleveldb -pthread -lgtest -lgmock
	@echo "Compile done."
	./${TARGET}

#${OBJ}:${SRC}
#   $(CC) ${CCFLAGS} -c $? 

test:
	./${TARGET}

$(OBJ):%.o:%.cc
	@echo "Compiling $< ==> $@"
	${CC} ${CCFLAGS} -c $< -o $@

clean:
	@rm -f ${OBJ}
	@echo "Clean object files done."

	@rm -f *~
	@echo "Clean tempreator files done."

	@rm -f ${TARGET}
	@echo "Clean target files done."

	@echo "Clean done."
