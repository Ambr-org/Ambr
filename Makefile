CUR_DIR=.

ARCH_DIR=${CUR_DIR}/arch/linux
SERVER_DIR=${CUR_DIR}/src/server
MAIN_DIR=${CUR_DIR}/src
LIB_DIR=${CUR_DIR}/libs
CROW_DIR=${CUR_DIR}/libs/crow
LEVELDB_DIR=${CUR_DIR}/libs/leveldb

INC_DIR= -I${ARCH_DIR} \
         -I${MAIN_DIR} \
		 -I${SERVER_DIR} \
		 -I${CROW_DIR}/include \
		 -I${LEVELDB_DIR}/include \
         -I${LIB_DIR}

SRC = ${wildcard  ${ARCH_DIR}/*.cc} \
	  ${wildcard  ${SERVER_DIR}/*.cc} \
      ${wildcard  ${LIB_DIR}/*.cc} \
	  ${wildcard  ${MAIN_DIR}/*.cc}

OBJ = ${patsubst %.cc, %.o, ${SRC}}

TARGET=ambr
CC=g++
CCFLAGS=-g -std=c++14 -Wall ${INC_DIR} -pthread

#g++ ./arch/linux/platform.o  ./src/server/ambrd.o  ./src/main.o -o ambr -lboost_system -pthread
${TARGET}: ${OBJ}
	${CC} ${OBJ} -o $@ -L${LEVELDB_DIR} -lboost_system -lleveldb -pthread 
	@echo "Compile done."

#${OBJ}:${SRC}
#   $(CC) ${CCFLAGS} -c $? 

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
