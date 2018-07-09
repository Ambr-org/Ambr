
#ifndef AMBR_CRYPTO_HASH_H_
#define AMBR_CRYPTO_HASH_H_
#include <stdint.h>
#include <utils/uint.h>
#include <blake2/blake2.h>
#include <boost/multiprecision/cpp_int.hpp>
namespace ambr {
namespace crypto {

/*
Calculate hash values
input: address of data for calculate
length:  length of data by BYTE
*/
template<typename T, uint32_t size>
T CalcHash(const void* input, size_t length)
{
  T number;
  blake2b_state hash_state;
  std::array<T, size> bytes;
	
  int status = blake2b_init(&hash_state, sizeof(T) * bytes.size());

  assert(0 == status);
  status =  blake2b_update(&hash_state, input, length);

  assert(0 == status);
  status = blake2b_final(&hash_state, bytes.data (), sizeof(T) * bytes.size());

  assert(0 == status);

  number.set_bytes(bytes);
  return number;
}

}
}

#endif
