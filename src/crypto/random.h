#ifndef AMBR_CRYPTO_RANDOM_H_
#define AMBR_CRYPTO_RANDOM_H_

#ifndef _WIN32
#include <cpuid.h>
#endif

#include <random>
#include <openssl/rand.h>
#include <time.h>
#include <fcntl.h>
#include "blake2/blake2.h"
namespace ambr {
namespace crypto {
/*
  example:
    ambr::core::PrivateKey key(ambr::crypto::Random::CreateRandomArray<32>());
*/
class Random{
public:
  template<int size>
  static std::array<uint8_t, size> CreateRandomArray(){
    blake2b_state hash_state;
    blake2b_init(&hash_state, size);
    #ifdef _WIN32
	  std::random_device rd;
	  auto random = rd();
	  blake2b_update(&hash_state, &random, sizeof(random));
    #else
	  RandCPU(hash_state);
	  RandOpenSSL(hash_state);
	  RandOpenOS(hash_state);
	  RandHardWare(hash_state);
    #endif
    RandTime(hash_state);
    std::array<uint8_t, size> array;
    blake2b_final(&hash_state, array.data(), array.size());
    return array;
  }
private:
#ifndef _WIN32
  static void RandCPU(blake2b_state& hash_state){
    uint32_t cup_id[4];
    __get_cpuid(1, &cup_id[0], &cup_id[1], &cup_id[2], &cup_id[3]);
    blake2b_update(&hash_state, (const unsigned char*)(&cup_id[0]), 4*4);
  }

  static void RandOpenSSL(blake2b_state& hash_state){
    unsigned char buf[32];
    uint64_t r1 = 0, r2 = 0;
    __asm__ volatile ("rdtsc" : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
    uint64_t r=  (r2 << 32) | r1;
    RAND_add(&r, sizeof(r), 1.5);
    RAND_bytes(buf, 32);
    blake2b_update(&hash_state, buf, 32);
  }

  static void RandOpenOS(blake2b_state& hash_state){
    unsigned char buf[32];
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        return;
    }
    int have = 0;
    do {
        ssize_t n = read(f, (unsigned char*)buf + have, 32 - have);
        if (n <= 0 || n + have > 32) {
            close(f);
            return;
        }
        have += n;
    } while (have < 32);
    close(f);
    blake2b_update(&hash_state, buf, 32);
  }

  static void RandHardWare(blake2b_state& hash_state){
    uint64_t r[4] = {0};
    uint8_t ok;
    __asm__ volatile (".byte 0x48, 0x0f, 0xc7, 0xf0, " // rdrand %rax
                            "0x48, 0x0f, 0xc7, 0xf3, " // rdrand %rbx
                            "0x48, 0x0f, 0xc7, 0xf1, " // rdrand %rcx
                            "0x48, 0x0f, 0xc7, 0xf2; " // rdrand %rdx
                      "setc %4" :
                      "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]), "=q"(ok) :: "cc");
    if (!ok) return;
    blake2b_update(&hash_state, (unsigned char*)(&r[0]), 32);
  }
#endif
  static void RandTime(blake2b_state& hash_state){
    time_t rawtime;
    time (&rawtime);
    blake2b_update(&hash_state, (unsigned char*)&rawtime, sizeof(rawtime));
  }
};

} //end crypto
} //end ambr

#endif
