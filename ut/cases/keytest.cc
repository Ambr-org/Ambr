
#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include "core/key.h"

TEST (KeyTest, HandleTrueReturn) {
  const ambr::core::PrivateKey& pri = ambr::core::CreateRandomPrivateKey();
  std::cout << "private key: " << pri.encode_to_hex() <<std::endl <<std::endl;

  const ambr::core::PublicKey& pub = ambr::core::GetPublicKeyByPrivateKey(pri);
  
  std::cout << "public key: "  << pub.encode_to_hex() <<std::endl <<std::endl;
return;
  std::string&& addr = ambr::core::GetAddressStringByPublicKey(pub);
  std::cout << "address: "  << addr <<std::endl <<std::endl;

return;
  const ambr::core::PublicKey& pub2 = ambr::core::GetPublicKeyByAddress(addr);
  std::cout << "address to public key: "  << pub2.encode_to_hex() <<std::endl <<std::endl;

  uint8_t* tmp = (uint8_t*)"bdjowngsjgl";
  ambr::core::Signature sign = ambr::core::GetSignByPrivateKey(tmp, strlen((char*)tmp), pri);
  std::cout << "signature: "  << sign.encode_to_hex() <<std::endl <<std::endl;

  bool ret = ambr::core::SignIsValidate(tmp, strlen((char*)tmp), pri, sign);

  ambr::utils::uint256 test;
  bool ret2 = ambr::core::SymEncrypting(pri, "sagsgsgs", test);
  std::cout << "Sym encryption: "  << test.encode_to_hex() <<std::endl <<std::endl;
  EXPECT_TRUE(ret);
}