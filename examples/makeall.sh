g++ leveldb.cc -o leveldb -std=c++14 -I../libs/leveldb/include -L../libs/leveldb/ -lleveldb -lpthread
g++ sha256.cc -o sha256 -std=c++14
g++ base64.cc -o base64 -std=c++14
g++ base58.cc -o base58 -std=c++14
g++ uint.cc -o uint -std=c++14 -I../src/utils/
g++ unit.cc ../src/core/unit.cc -o unit -std=c++14 -I../src
