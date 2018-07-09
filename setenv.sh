patch -p0 < ed25519-donna.patch
cd libs/ed25519-donna
rm test* regression.h README.md -r fuzz
cd ../leveldb
cmake -DCMAKE_BUILD_TYPE=Release . && cmake --build .
