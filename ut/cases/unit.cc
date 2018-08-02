
#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include "core/key.h"
#include <core/unit.h>
#include <store/unit_store.h>
#include <crypto/random.h>
#include <glog/logging.h>
#define SERIALIZE_EQ_TEST(unit_for_test) \
{\
  decltype(unit_for_test)::element_type  unit_tmp;\
  std::string str1 = unit_for_test->SerializeJson();\
  unit_tmp.DeSerializeJson(str1);\
  EXPECT_EQ(str1, unit_tmp.SerializeJson());\
  \
  std::vector<uint8_t> buf1 = unit_for_test->SerializeByte();\
  unit_tmp.DeSerializeByte(buf1);\
  EXPECT_EQ(buf1, unit_tmp.SerializeByte());\
}

#define SERIALIZE_EQ_TEST_ASSIST(unit_for_test) \
  decltype(unit_for_test)::element_type  unit_tmp;\
  std::string str1 = unit_for_test->SerializeJson();\
  unit_tmp.DeSerializeJson(str1);\
  EXPECT_EQ(str1, unit_tmp.SerializeJson());\
  \
  std::vector<uint8_t> buf1 = unit_for_test->SerializeByte();\
  unit_tmp.DeSerializeByte(buf1);\
  EXPECT_EQ(buf1, unit_tmp.SerializeByte());

#define SERIALIZE_EQ_TEST_VALUE(unit_for_test, param, value) \
{\
  unit_for_test->set_##param(value); \
  SERIALIZE_EQ_TEST_ASSIST(unit_for_test);\
  auto x = unit_tmp.param();\
  EXPECT_EQ(x, value);\
}

TEST (UnitTest, SendUnit_and_SendUnitStore) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::SendUnit> unit1 = std::make_shared<ambr::core::SendUnit>();
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, ((uint32_t)0x00000001));
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::send);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE(unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);
  SERIALIZE_EQ_TEST_VALUE(unit1, dest, pub_key);
  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));

  std::shared_ptr<ambr::store::SendUnitStore> unit2 = std::make_shared<ambr::store::SendUnitStore>(unit1);
  SERIALIZE_EQ_TEST(unit2);
  SERIALIZE_EQ_TEST_VALUE(unit2, receive_unit_hash, unit_hash_rand);
  SERIALIZE_EQ_TEST_VALUE(unit2, type, ambr::store::UnitStore::ST_SendUnit);
  SERIALIZE_EQ_TEST_VALUE(unit2, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit2, is_validate, true);

}

TEST (UnitTest, ReceiveUnit_and_ReceiveUnitStore) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::ReceiveUnit> unit1 = std::make_shared<ambr::core::ReceiveUnit>();
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::receive);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE( unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);
  SERIALIZE_EQ_TEST_VALUE(unit1, from, pub_key);
  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));

  std::shared_ptr<ambr::store::ReceiveUnitStore> unit2 = std::make_shared<ambr::store::ReceiveUnitStore>(unit1);
  SERIALIZE_EQ_TEST(unit2);
  SERIALIZE_EQ_TEST_VALUE(unit2, type, ambr::store::UnitStore::ST_ReceiveUnit);
  SERIALIZE_EQ_TEST_VALUE(unit2, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit2, is_validate, true);
}

TEST (UnitTest, EnterValidateSetUint) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::EnterValidateSetUint> unit1 = std::make_shared<ambr::core::EnterValidateSetUint>();
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
  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));
}

TEST (UnitTest, LeaveValidateSetUint) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::LeaveValidateSetUint> unit1 = std::make_shared<ambr::core::LeaveValidateSetUint>();
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::LeaveValidateSet);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE(unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::core::Amount unfreeze_count_tmp = (boost::multiprecision::uint128_t)12345;
  SERIALIZE_EQ_TEST_VALUE(unit1, unfreeze_count, unfreeze_count_tmp);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);
  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));
}
