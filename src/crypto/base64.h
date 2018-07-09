/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Written by kan                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <string>
#include <string.h>

#ifndef AMBR_CRYPTO_BASE64_H_
#define AMBR_CRYPTO_BASE64_H_

namespace ambr {
namespace crypto {

static const char* kBase64Table = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static const char kPadding = '=';

static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

size_t encoded_length(size_t input_len) {
  size_t n = input_len;
  return (n + 2 - ((n + 2) % 3)) / 3 * 4;
}

size_t decoded_length(const char * input, size_t input_len) {
  size_t i = 0;
  size_t num = 0;

  for(i = input_len - 1; input[i] == kPadding; --i) {
    num++;
  }
  return ((6 * input_len) / 8) - num;
}

//Private utility functions
inline void c3_to_c4(const char * c3, char * c4) {
  c4[0] = (c3[0] & 0xfc) >> 2;
  c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
  c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
  c4[3] = (c3[2] & 0x3f);
}

inline void c4_to_c3(const char * c4, char * c3) {
  c3[0] = (c4[0] << 2) + ((c4[1] & 0x30) >> 4);
  c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
  c3[2] = ((c4[2] & 0x3) << 6) + c4[3];
}

inline unsigned char to_ascii(char c) {
  if(c >='A' && c <='Z') return c - 'A';
  if(c >='a' && c <='z') return c - 71;
  if(c >='0' && c <='9') return c + 4;
  if(c == '+') return 62;
  if(c == '/') return 63;
  return -1;
}

inline void translate (char* c4, size_t len) {
  for(size_t i = 0; i < len; ++i) {
      c4[i] = kBase64Table[(int)(c4[i])];
  }
}

inline void padding(char* buf, size_t start, size_t end) {
  for(size_t i = start; i < end; ++i) {
    buf[i] = kPadding;
  }
}

size_t base64_encode(const char* input, size_t input_len, char* output) {
  size_t m = input_len / 3;
  size_t n = input_len % 3;

  for (size_t i = 0; i < m; ++i) {
    const char* c3 = input + (i * 3);
    char* c4 = output + (i * 4);
    c3_to_c4(c3, c4);
    translate(c4, 4);
  }
  if (n > 0) {
    char c3[3] = {'\0'};
    char* c4 = output + (m * 4);

    memcpy(c3, input + (3 * m), n);
    c3_to_c4(c3, c4);
    translate(c4, n + 1);
    padding(c4, n + 1, 4);
  }
  size_t sum = m * 4 + (n > 0 ? 4 : 0);
  if (sum > 0) {
    output[sum] = '\0';
  }
  return sum;
}

inline void c4_to_c3_unpadding(const char* c4, char* c3) {
  char c4_2[4] = {'\0'};
  for(size_t i = 0; i < 4; ++i) {
    if(c4[i] != kPadding) {
      c4_2[i] = to_ascii(c4[i]);
    }
  }
  c4_to_c3(c4_2, c3);
}

size_t base64_decode(const char * input, size_t input_len, char * output) {
  if(input_len % 4 != 0) {
    return 0;
  }
  for(size_t i = 0; i < input_len/ 4; ++i) {
    const char* c4 = input + i * 4;
    char* c3 = output + i * 3;
    c4_to_c3_unpadding(c4, c3);
  }
  size_t sum = input_len / 4 * 3;
  output[sum] = '\0';
  return sum;
}

//base64 decode
bool base64_decode(const char* input, size_t input_len, std::string& result) {
  auto decoded_len = decoded_length(input, input_len);
  char* target = new char[decoded_len];
  if (target) {
    auto result_len = base64_decode(input, input_len, target);
    result = target;
    delete[] target;
    return result_len > 0;
  }
  return false;
}

bool base64_decode(const std::string& input, std::string& result) {
  return base64_decode(input.c_str(), input.size(), result);
}

//base64 encode
bool base64_encode(const char* input, size_t input_len, std::string& result) {
  auto encoded_len = encoded_length(input_len);
  char* target = new char[encoded_len];
  if(target) {
    auto result_len = base64_encode(input, input_len, target);
    result = target;
    delete[] target;
    return result_len > 0;
  }
  return false;
}

bool base64_encode(const std::string& input, std::string& result) {
  return base64_encode(input.c_str(), input.size(), result);
}

};
};

#endif