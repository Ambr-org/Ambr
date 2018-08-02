
#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include "core/key.h"
#include <core/unit.h>
#include <crypto/random.h>
#include <glog/logging.h>
#define SERIALIZE_EQ_TEST(unit_for_test) \
{\
  ambr::core::EnterValidateSetUint  unit_tmp;\
  std::string str1 = unit_for_test.SerializeJson();\
  unit_tmp.DeSerializeJson(str1);\
  EXPECT_EQ(str1, unit_tmp.SerializeJson());\
  \
  std::vector<uint8_t> buf1 = unit_for_test.SerializeByte();\
  unit_tmp.DeSerializeByte(buf1);\
  EXPECT_EQ(buf1, unit_tmp.SerializeByte());\
}

#define SERIALIZE_EQ_TEST_ASSIST(unit_for_test) \
  ambr::core::EnterValidateSetUint  unit_tmp;\
  std::string str1 = unit_for_test.SerializeJson();\
  unit_tmp.DeSerializeJson(str1);\
  EXPECT_EQ(str1, unit_tmp.SerializeJson());\
  \
  std::vector<uint8_t> buf1 = unit_for_test.SerializeByte();\
  unit_tmp.DeSerializeByte(buf1);\
  EXPECT_EQ(buf1, unit_tmp.SerializeByte());

int version(){
  return 0;
}
class xxx{
public:
  static int  version(){
    return 0;
  }
};
#define SERIALIZE_EQ_TEST_VALUE(unit_for_test, param, value) \
{\
  unit_for_test.set_##param(value); \
  SERIALIZE_EQ_TEST_ASSIST(unit_for_test);\
  auto x = unit_tmp.param();\
  EXPECT_EQ(x, value);\
}

TEST (UnitTest, EnterValidateSetUint) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  ambr::core::EnterValidateSetUint unit1;
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::EnterValidateSet);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE(unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);
  unit1.CalcHashAndFill();
  unit1.SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1.Validate(nullptr));
  std::cout<<unit1.SerializeJson()<<std::endl;
}

TEST (UnitTest, LeaveValidateSetUint) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  ambr::core::LeaveValidateSetUint unit1;
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::LeaveValidateSet);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE(unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);
  unit1.CalcHashAndFill();
  unit1.SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1.Validate(nullptr));
  std::cout<<unit1.SerializeJson()<<std::endl;
}
