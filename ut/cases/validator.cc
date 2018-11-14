
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
  std::cout<<"<ValidatorTest.JoinValidator>:init db"<<std::endl;
  system("rm -fr ./bbb");
  manager->Init("./bbb");

  ambr::core::UnitHash test_hash;
  std::shared_ptr<ambr::core::Unit> added_unit;
  std::string err;
  ambr::core::PrivateKey validator_pri[5];
  std::cout<<"<ValidatorTest.JoinValidator>:create 5 user"<<std::endl;
  for(size_t i = 0; i < sizeof(validator_pri)/sizeof(ambr::core::PrivateKey); i++){
    validator_pri[i] = ambr::core::CreateRandomPrivateKey();
    EXPECT_TRUE(manager->SendToAddress(ambr::core::GetPublicKeyByPrivateKey(validator_pri[i]), ambr::store::StoreManager::GetMinValidatorBalance()+10000, root_pri_key, &test_hash, added_unit, &err));
    EXPECT_TRUE(manager->ReceiveFromUnitHash(test_hash, validator_pri[i], &test_hash, added_unit, &err));
  }
  std::cout<<"<ValidatorTest.JoinValidator>:user1 first enter test"<<std::endl;
  EXPECT_FALSE(manager->JoinValidatorSet(validator_pri[0], ambr::store::StoreManager::GetMinValidatorBalance(), &test_hash, added_unit, &err));
  EXPECT_TRUE(manager->JoinValidatorSet(validator_pri[0],
    ambr::store::StoreManager::GetMinValidatorBalance()+ambr::core::EnterValidateSetUnit().GetFeeSize()*ambr::store::StoreManager::GetTransectionFeeBase(),
    &test_hash, added_unit, &err));
  //twice enter validator set
  std::cout<<"<ValidatorTest.JoinValidator>:user1 twice enter test"<<std::endl;
  EXPECT_FALSE(manager->JoinValidatorSet(validator_pri[0],
    ambr::store::StoreManager::GetMinValidatorBalance()+ambr::core::EnterValidateSetUnit().GetFeeSize()*ambr::store::StoreManager::GetTransectionFeeBase(),
    &test_hash, added_unit, &err));


  std::cout<<"<ValidatorTest.JoinValidator>:leave validator when it didn't enter validator set"<<std::endl;
  EXPECT_FALSE(manager->LeaveValidatorSet(validator_pri[0], &test_hash, added_unit, &err));

  std::cout<<"<ValidatorTest.JoinValidator>:vote unit befor now"<<std::endl;
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
  std::cout<<"<ValidatorTest.JoinValidator>:check whether user has entered validator set "<<std::endl;
  EXPECT_TRUE(manager->GetValidatorSet()->IsValidator(ambr::core::GetPublicKeyByPrivateKey(validator_pri[0])));

  std::cout<<"<ValidatorTest.JoinValidator>:user1 leave validator set"<<std::endl;
  EXPECT_TRUE(manager->LeaveValidatorSet(validator_pri[0], &test_hash, added_unit, &err));
  //twice leave will has no effective but pay tansection fee
  EXPECT_TRUE(manager->LeaveValidatorSet(validator_pri[0], &test_hash, added_unit, &err));
  //can't get validate's income when leave unit haven't validated
  EXPECT_FALSE(manager->ReceiveFromValidator(validator_pri[0], &test_hash, added_unit, &err));
  //wait twice validate's interval
  boost::this_thread::sleep(boost::posix_time::millisec(manager->GetValidateUnitInterval()));
  EXPECT_TRUE(manager->PublishValidator(root_pri_key, &test_hash, unit_validator, &err));
  EXPECT_TRUE(manager->PublishVote(root_pri_key, true, vote_unit, &err));

  //receive validate's income will faild when once validate
  EXPECT_FALSE(manager->ReceiveFromValidator(validator_pri[0], &test_hash, added_unit, &err));
  boost::this_thread::sleep(boost::posix_time::millisec(manager->GetValidateUnitInterval()));
  EXPECT_TRUE(manager->PublishValidator(root_pri_key, &test_hash, unit_validator, &err));
  EXPECT_TRUE(manager->PublishVote(root_pri_key, true, vote_unit, &err));
  std::cout<<"<ValidatorTest.JoinValidator>:check whether user has entered validator set "<<std::endl;
  EXPECT_FALSE(manager->GetValidatorSet()->IsValidator(ambr::core::GetPublicKeyByPrivateKey(validator_pri[0])));
  //receive validate's income
  EXPECT_TRUE(manager->ReceiveFromValidator(validator_pri[0], &test_hash, added_unit, &err));



}

