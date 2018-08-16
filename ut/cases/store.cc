
#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include <glog/logging.h>

#include "store/store_manager.h"
/*
class StoreManager{
public:
  StoreManager();
public:
  void Init(const std::string& path);
  //callback
  boost::signals2::connection AddCallBackReceiveNewSendUnit(std::function<void(std::shared_ptr<core::SendUnit>)> callback);
  boost::signals2::connection AddCallBackReceiveNewReceiveUnit(std::function<void(std::shared_ptr<core::ReceiveUnit>)> callback);
  boost::signals2::connection AddCallBackReceiveNewJoinValidatorSetUnit(std::function<void(std::shared_ptr<core::EnterValidateSetUint>)> callback);
  boost::signals2::connection AddCallBackReceiveNewLeaveValidatorSetUnit(std::function<void(std::shared_ptr<core::LeaveValidateSetUint>)> callback);
  boost::signals2::connection AddCallBackReceiveNewValidatorUnit(std::function<void(std::shared_ptr<core::ValidatorUnit>)> callback);
public:
  //bool AddUnit(std::shared_ptr<core::Unit> unit, std::string* err);
  bool AddSendUnit(std::shared_ptr<core::SendUnit> send_unit, std::string* err);
  bool AddReceiveUnit(std::shared_ptr<core::ReceiveUnit> receive_unit, std::string* err);
  bool AddEnterValidatorSetUnit(std::shared_ptr<core::EnterValidateSetUint> unit, std::string* err);
  bool AddLeaveValidatorSetUnit(std::shared_ptr<core::LeaveValidateSetUint> unit, std::string* err);
  bool AddValidateUnit(std::shared_ptr<core::ValidatorUnit> unit, std::string* err);
  bool AddVote(std::shared_ptr<core::VoteUnit> unit, std::string* err);
  void ClearVote();
  void UpdateNewUnitMap(const std::vector<core::UnitHash>& validator_check_list);

  bool GetLastValidateUnit(core::UnitHash& hash);
  std::list<std::shared_ptr<core::ValidatorUnit>> GetValidateHistory(size_t count);
  bool GetLastUnitHashByPubKey(const core::PublicKey& pub_key, core::UnitHash& hash);
  bool GetBalanceByPubKey(const core::PublicKey& pub_key, core::Amount& balance);
  std::list<std::shared_ptr<store::UnitStore>>
    GetTradeHistoryByPubKey(const core::PublicKey& pub_key, size_t count);
  bool GetSendAmount(const ambr::core::UnitHash &unit_hash, core::Amount& amount, std::string* err);
  //get all new unit map at lastest of account  which is not validated by validator set
  std::unordered_map<ambr::core::PublicKey, ambr::core::UnitHash>
    GetNewUnitMap();
  std::shared_ptr<store::ValidatorSetStore> GetValidatorSet();
  bool SendToAddress(
      const core::PublicKey pub_key_to,
      const core::Amount& count,
      const core::PrivateKey& prv_key,
      core::UnitHash* tx_hash,
      std::shared_ptr<ambr::core::Unit>& unit_sended,
      std::string* err);
  bool ReceiveFromUnitHash(
      const core::UnitHash unit_hash,
      const core::PrivateKey& pri_key,
      core::UnitHash* tx_hash,
      std::shared_ptr<ambr::core::Unit>& unit_received,
      std::string* err);
  bool JoinValidatorSet(const core::PrivateKey& pri_key,
                        const core::Amount& count,
                        core::UnitHash* tx_hash,
                        std::shared_ptr<ambr::core::Unit>& unit_join,
                        std::string* err);
  bool LeaveValidatorSet(const core::PrivateKey& pri_key,
                         const core::Amount& count,
                         core::UnitHash* tx_hash,
                         std::shared_ptr<ambr::core::Unit>& unit_leave,
                         std::string* err);
  //add ValidatorUnit auto Validate Unit
  bool PublishValidator(const core::PrivateKey& pri_key,
                        core::UnitHash* tx_hash,
                        std::shared_ptr<ambr::core::ValidatorUnit>& unit_validator,
                        std::string* err);
  bool PublishVote(const core::PrivateKey& pri_key,
                   bool accept,
                   std::shared_ptr<ambr::core::VoteUnit>& unit_vote,
                   std::string* err);
  std::list<core::UnitHash> GetWaitForReceiveList(const core::PublicKey& pub_key);
  //get unit(send_unit and receive_unit)
  std::shared_ptr<UnitStore> GetUnit(const core::UnitHash& hash);
  std::shared_ptr<SendUnitStore> GetSendUnit(const core::UnitHash& hash);
  std::shared_ptr<ReceiveUnitStore> GetReceiveUnit(const core::UnitHash& hash);
  std::shared_ptr<core::ValidatorUnit> GetValidateUnit(const core::UnitHash& hash);
  std::shared_ptr<core::ValidatorUnit> GetLastestValidateUnit();
  std::shared_ptr<EnterValidatorSetUnitStore> GetEnterValidatorSetUnit(const core::UnitHash& hash);
  std::shared_ptr<LeaveValidatorSetUnitStore> GetLeaveValidatorSetUnit(const core::UnitHash& hash);
  std::list<std::shared_ptr<core::VoteUnit>> GetVoteList();

  uint64_t GetGenesisTime(){return genesis_time_;}
  uint32_t GetValidateUnitInterval(){return validate_unit_interval_;}
  uint64_t GetPassPercent(){return PASS_PERCENT;}
  uint64_t GetNonceByNowTime();
  std::recursive_mutex& GetMutex(){return mutex_;}
*/
TEST (UnitTest, Store) {
  std::string root_pri_key = "25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC";
  ambr::store::StoreManager* manager = new ambr::store::StoreManager();
  ambr::core::PrivateKey test_pri = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(test_pri);
  manager->Init("aaa");
  ambr::core::UnitHash test_hash;
  std::shared_ptr<ambr::core::Unit> added_unit;
  ambr::core::Amount send_ammout = 1;
  std::string err;
  ambr::core::Amount balance_ori;
  ambr::core::Amount balance_used;
  ambr::core::Amount balance_remainder;

  //==============================
  //test send 1
  {
    //regular opration
    EXPECT_TRUE(manager->GetBalanceByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), balance_ori));
    for(int i = 0; i < 12; i++){
      balance_used = balance_used+send_ammout;
      bool result;
      EXPECT_TRUE((result = manager->SendToAddress(test_pub, send_ammout, root_pri_key, &test_hash, added_unit, &err)));
      if(!result){
        std::cout<<err<<std::endl;
      }
      send_ammout = send_ammout*10;
    }
    //param test
    EXPECT_TRUE(manager->SendToAddress(test_pub, 1, root_pri_key, nullptr, added_unit, nullptr));
    balance_used = balance_used+1;
    EXPECT_TRUE(manager->GetBalanceByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), balance_remainder));
    EXPECT_EQ(balance_remainder, balance_ori-balance_used);

    //incorrect opration
    //error private key
    EXPECT_FALSE(manager->SendToAddress(test_pub, send_ammout, ambr::core::CreateRandomPrivateKey(), &test_hash, added_unit, &err));
    //error send_ammout(bigger than remainder)
    EXPECT_FALSE(manager->SendToAddress(test_pub, balance_remainder+1, root_pri_key, &test_hash, added_unit, &err));
  }

  //==============================
  //test send 2
  {
    //regular opration
    std::shared_ptr<ambr::core::SendUnit> send_unit = std::make_shared<ambr::core::SendUnit>();
    std::list<std::shared_ptr<ambr::store::UnitStore> > trade_history = manager->GetTradeHistoryByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), 10);
    send_unit->set_version((uint32_t)0x00000001);
    send_unit->set_type(ambr::core::UnitType::send);
    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(root_pri_key));
    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->set_balance(balance_remainder - 10000);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_TRUE(manager->AddSendUnit(send_unit, nullptr));

    //incorrect opration
    send_unit->set_version((uint32_t)0x00000002);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_version((uint32_t)0x00000001);
    send_unit->set_type(ambr::core::UnitType::receive);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_type(ambr::core::UnitType::send);
    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(test_pri));
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(test_pri);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(root_pri_key));
    send_unit->set_prev_unit(trade_history.back()->GetUnit()->hash());
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->CalcHashAndFill();
    send_unit->set_balance(balance_remainder +1);
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));


    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->set_balance(balance_remainder +1);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_balance(balance_remainder);
    send_unit->set_hash(ambr::core::CreateRandomPrivateKey());
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->CalcHashAndFill();
    send_unit->set_sign(ambr::core::Signature());
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));
  }
  {//test receive1
    std::list<ambr::core::UnitHash> wait_list = manager->GetWaitForReceiveList(test_pub);
    for(ambr::core::UnitHash hash: wait_list){

    }
  }
}
