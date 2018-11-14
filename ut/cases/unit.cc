
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
  decltype(unit_for_test)::element_type  unit_tmp1;\
  std::vector<uint8_t> buf1 = unit_for_test->SerializeByte();\
  unit_tmp1.DeSerializeByte(buf1);\
  EXPECT_EQ(buf1, unit_tmp1.SerializeByte());

#define SERIALIZE_EQ_TEST_VALUE(unit_for_test, param, value) \
{\
  unit_for_test->set_##param(value); \
  SERIALIZE_EQ_TEST_ASSIST(unit_for_test);\
  auto x = unit_tmp.param();\
  EXPECT_EQ(x, value);\
  auto y = unit_tmp1.param();\
  EXPECT_EQ(y, value);\
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

  SERIALIZE_EQ_TEST_VALUE(unit1, data_type, (ambr::core::SendUnit::DataType)2 );
  SERIALIZE_EQ_TEST_VALUE(unit1, data, "1234567890");


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

TEST (UnitTest, VoteUnit) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::VoteUnit> unit1 = std::make_shared<ambr::core::VoteUnit>();
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::Vote);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE(unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);

  ambr::core::UnitHash random_hash;
  random_hash.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, validator_unit_hash, random_hash);

  SERIALIZE_EQ_TEST_VALUE(unit1, accept, true);

  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));
}

TEST (UnitTest, ValidatorUnit) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::ValidatorUnit> unit1 = std::make_shared<ambr::core::ValidatorUnit>();
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);
  SERIALIZE_EQ_TEST_VALUE(unit1, type, ambr::core::UnitType::Validator);
  SERIALIZE_EQ_TEST_VALUE(unit1, public_key, pub_key);
  SERIALIZE_EQ_TEST_VALUE(unit1, prev_unit, unit_hash_rand);
  ambr::core::Amount amount;
  amount.set_data(123123123);
  SERIALIZE_EQ_TEST_VALUE(unit1, balance, amount);
  SERIALIZE_EQ_TEST_VALUE(unit1, hash, unit_hash_rand);
  ambr::utils::uint512 sign_tmp;
  sign_tmp.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp);

  ambr::core::UnitHash check_hash_1;
  check_hash_1.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  ambr::core::UnitHash check_hash_2;
  check_hash_2.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::vector<ambr::core::UnitHash> check_list_tmp;
  check_list_tmp.push_back(check_hash_1);
  check_list_tmp.push_back(check_hash_2);
  unit1->set_check_list(check_list_tmp);
  SERIALIZE_EQ_TEST_VALUE(unit1, check_list, check_list_tmp);

  ambr::core::VoteUnit VoteUnit_1;
  VoteUnit_1.set_version((uint32_t)0x00000001);

  VoteUnit_1.set_type(ambr::core::UnitType::Vote);

  ambr::core::PrivateKey pri_key_1 = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key_1 = ambr::core::GetPublicKeyByPrivateKey(pri_key_1);
  VoteUnit_1.set_public_key(pub_key_1);

  ambr::core::UnitHash prev_hash_1;
  prev_hash_1.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());
  VoteUnit_1.set_prev_unit(prev_hash_1);

  ambr::core::Amount amount_1;
  amount_1.set_data(123123123);
  VoteUnit_1.set_balance(amount_1);

  ambr::core::UnitHash rand_hash_1;
  rand_hash_1.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());
  VoteUnit_1.set_validator_unit_hash(rand_hash_1);

  ambr::utils::uint512 sign_tmp_1;
  sign_tmp_1.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp_1);

  VoteUnit_1.set_accept(true);
  VoteUnit_1.CalcHashAndFill();
  VoteUnit_1.SignatureAndFill(pri_key_1);
  EXPECT_TRUE(VoteUnit_1.Validate(nullptr));

  ambr::core::VoteUnit VoteUnit_2;
  VoteUnit_2.set_version((uint32_t)0x00000001);
  VoteUnit_2.set_type(ambr::core::UnitType::Vote);
  ambr::core::PrivateKey pri_key_2 = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key_2= ambr::core::GetPublicKeyByPrivateKey(pri_key_2);
  VoteUnit_2.set_public_key(pub_key_2);
  ambr::core::UnitHash prev_hash_2;
  prev_hash_2.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());
  VoteUnit_2.set_prev_unit(prev_hash_2);
  ambr::core::Amount amount_2;
  amount_2.set_data(123123121);
  VoteUnit_2.set_balance(amount_2);
  ambr::core::UnitHash rand_hash_2;
  rand_hash_2.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());
  VoteUnit_2.set_validator_unit_hash(rand_hash_2);
  VoteUnit_2.set_accept(true);

  ambr::utils::uint512 sign_tmp_2;
  sign_tmp_2.set_bytes(ambr::crypto::Random::CreateRandomArray<512/8>());
  SERIALIZE_EQ_TEST_VALUE(unit1, sign, sign_tmp_2);

  VoteUnit_2.CalcHashAndFill();
  VoteUnit_2.SignatureAndFill(pri_key_2);

  std::string error_string;
  EXPECT_TRUE(VoteUnit_2.Validate(&error_string));

  std::vector<ambr::core::VoteUnit> vote_list_tmp;
  vote_list_tmp.push_back(VoteUnit_1);
  vote_list_tmp.push_back(VoteUnit_2);
  SERIALIZE_EQ_TEST_VALUE(unit1, vote_list, vote_list_tmp);


  ambr::core::UnitHash vote_hash_list_1;
  vote_hash_list_1=VoteUnit_1.hash();
  ambr::core::UnitHash vote_hash_list_2;
  vote_hash_list_2=VoteUnit_2.hash();
  std::vector<ambr::core::UnitHash> vote_hash_list_tmp;
  vote_hash_list_tmp.push_back(vote_hash_list_1);
  vote_hash_list_tmp.push_back(vote_hash_list_2);

  SERIALIZE_EQ_TEST_VALUE(unit1, vote_hash_list, vote_hash_list_tmp);

  SERIALIZE_EQ_TEST_VALUE(unit1, percent, (uint32_t)100998);
  SERIALIZE_EQ_TEST_VALUE(unit1, nonce, (uint64_t)89888);
  SERIALIZE_EQ_TEST_VALUE(unit1, time_stamp,(uint64_t)87658);
  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));
}

TEST (UnitTest, EnterValidateSetUnit) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::EnterValidateSetUnit> unit1 = std::make_shared<ambr::core::EnterValidateSetUnit>();
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

TEST (UnitTest, LeaveValidateSetUnit) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  ambr::core::UnitHash unit_hash_rand;
  unit_hash_rand.set_bytes(ambr::crypto::Random::CreateRandomArray<256/8>());

  std::shared_ptr<ambr::core::LeaveValidateSetUnit> unit1 = std::make_shared<ambr::core::LeaveValidateSetUnit>();
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
  unit1->CalcHashAndFill();
  unit1->SignatureAndFill(pri_key);
  EXPECT_TRUE(unit1->Validate(nullptr));
}

TEST (UnitTest, ValidatorSetStore) {
  ambr::core::PrivateKey pri_key = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  std::shared_ptr<ambr::store::ValidatorSetStore> unit1 = std::make_shared<ambr::store::ValidatorSetStore>();
  SERIALIZE_EQ_TEST(unit1);
  SERIALIZE_EQ_TEST_VALUE(unit1, version, (uint32_t)0x00000001);

  std::list<ambr::store::ValidatorItem> list_tmp;
  ambr::store::ValidatorItem item_tmp;
  item_tmp.balance_ = 1;
  item_tmp.enter_nonce_ = 11;
  item_tmp.leave_nonce_ = 111;
  item_tmp.validator_public_key_ = pub_key;
  list_tmp.push_back(item_tmp);
  item_tmp.balance_ = 2;
  item_tmp.enter_nonce_ = 22;
  item_tmp.leave_nonce_ = 222;
  item_tmp.validator_public_key_ = pub_key;
  list_tmp.push_back(item_tmp);
  SERIALIZE_EQ_TEST_VALUE(unit1, validator_list, list_tmp);

}
