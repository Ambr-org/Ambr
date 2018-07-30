cd libs/rocksdb/ && cmake .  -DMAKECMDGOALS=static_lib -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=Release && make VERBOSE=1 -j4 && cd ../glog/ && ./autogen.sh && ./configure && make
