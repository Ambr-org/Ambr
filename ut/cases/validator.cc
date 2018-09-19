
#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include <glog/logging.h>

#include "store/store_manager.h"
#include <boost/thread.hpp>
TEST (ValidatorTest, JoinValidator) {
  std::string root_pri_key = "25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC";
  ambr::store::StoreManager* manager = new ambr::store::StoreManager();
  //ambr::core::PrivateKey test_pri = ambr::core::CreateRandomPrivateKey();
  //ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(test_pri);

  system("rm -fr ./bbb");
  manager->Init("./bbb");

  ambr::core::UnitHash test_hash;
  std::shared_ptr<ambr::core::Unit> added_unit;
  std::string err;
  ambr::core::PrivateKey validator_pri[5];
  for(size_t i = 0; i < sizeof(validator_pri)/sizeof(ambr::core::PrivateKey); i++){
    validator_pri[i] = ambr::core::CreateRandomPrivateKey();
    EXPECT_TRUE(manager->SendToAddress(ambr::core::GetPublicKeyByPrivateKey(validator_pri[i]), ambr::store::StoreManager::GetMinValidatorBalance()+10000, root_pri_key, &test_hash, added_unit, &err));
    EXPECT_TRUE(manager->ReceiveFromUnitHash(test_hash, validator_pri[i], &test_hash, added_unit, &err));
  }
  EXPECT_FALSE(manager->JoinValidatorSet(validator_pri[0], ambr::store::StoreManager::GetMinValidatorBalance(), &test_hash, added_unit, &err));
  EXPECT_TRUE(manager->JoinValidatorSet(validator_pri[0],
    ambr::store::StoreManager::GetMinValidatorBalance()+ambr::core::EnterValidateSetUint().GetFeeSize()*ambr::store::StoreManager::GetTransectionFeeBase(),
    &test_hash, added_unit, &err));
  //twice enter validator set
  EXPECT_FALSE(manager->JoinValidatorSet(validator_pri[0],
    ambr::store::StoreManager::GetMinValidatorBalance()+ambr::core::EnterValidateSetUint().GetFeeSize()*ambr::store::StoreManager::GetTransectionFeeBase(),
    &test_hash, added_unit, &err));

  //leave validator when it didn't enter validator set
  EXPECT_FALSE(manager->LeaveValidatorSet(validator_pri[0], &test_hash, added_unit, &err));

  std::shared_ptr<ambr::core::ValidatorUnit> unit_validator;
  std::shared_ptr<ambr::core::VoteUnit> vote_unit;

  EXPECT_FALSE(manager->GetValidatorSet()->IsValidator(ambr::core::GetPublicKeyByPrivateKey(validator_pri[0])));
  boost::this_thread::sleep(boost::posix_time::millisec(manager->GetValidateUnitInterval()));
  EXPECT_TRUE(manager->PublishValidator(root_pri_key, &test_hash, unit_validator, &err));
  EXPECT_TRUE(manager->PublishVote(root_pri_key, true, vote_unit, &err));

  EXPECT_FALSE(manager->GetValidatorSet()->IsValidator(ambr::core::GetPublicKeyByPrivateKey(validator_pri[0])));
  boost::this_thread::sleep(boost::posix_time::millisec(manager->GetValidateUnitInterval()));
  EXPECT_TRUE(manager->PublishValidator(root_pri_key, &test_hash, unit_validator, &err));
  EXPECT_TRUE(manager->PublishVote(root_pri_key, true, vote_unit, &err));

  EXPECT_TRUE(manager->GetValidatorSet()->IsValidator(ambr::core::GetPublicKeyByPrivateKey(validator_pri[0])));



}

