
#include <utils/uint.h>
#include <iostream>

int main(){
  using namespace ambr::utils;
  uint256 exp;
  exp.decode_from_hex("00012acd00012acd00012acd00012acd00012acd00012acd00012acd00012acd");
  std::cout<<exp.encode_to_hex()<<std::endl;
  return 0;
}
