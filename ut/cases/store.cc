
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

  //===last_unit_hash===========================
  //test send 1----->SendToAddress
  {
    //regular operate
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

    //incorrect operate
    //error private key
    EXPECT_FALSE(manager->SendToAddress(test_pub, send_ammout, ambr::core::CreateRandomPrivateKey(), &test_hash, added_unit, &err));
    //error send_ammout(bigger than remainder)
    EXPECT_FALSE(manager->SendToAddress(test_pub, balance_remainder+1, root_pri_key, &test_hash, added_unit, &err));
  }

  //==============================
  //test send 2
  {
    //regular operate------>AddSendUnit
    std::shared_ptr<ambr::core::SendUnit> send_unit = std::make_shared<ambr::core::SendUnit>();
    std::list<std::shared_ptr<ambr::store::UnitStore> > trade_history = manager->GetTradeHistoryByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), 10);
    send_unit->set_version((uint32_t)0x00000001);
    send_unit->set_type(ambr::core::UnitType::send);
    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(root_pri_key));
    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->set_balance(balance_remainder - 10000);
    send_unit->set_dest(test_pub);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_TRUE(manager->AddSendUnit(send_unit, nullptr));

    //incorrect operate
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
  {//test receive1 ------>ReceiveFromUnitHash
    //regular operate
    std::list<ambr::core::UnitHash> wait_list = manager->GetWaitForReceiveList(test_pub);
    EXPECT_TRUE(wait_list.size() == 14);
    for(size_t i = 0; i < 13; i++){
      {//incorrect operate
        EXPECT_FALSE(manager->ReceiveFromUnitHash("12345", test_pri, &test_hash, added_unit, &err));
        EXPECT_FALSE(manager->ReceiveFromUnitHash(wait_list.front(), test_pri+1, &test_hash, added_unit, &err));
      }
      EXPECT_TRUE(manager->ReceiveFromUnitHash(wait_list.front(), test_pri, &test_hash, added_unit, &err));
      wait_list.pop_front();
    }
    ambr::core::Amount test_amount;
    EXPECT_TRUE(manager->GetBalanceByPubKey(test_pub, test_amount));
    EXPECT_TRUE(test_amount == balance_used);
  }

  {//test receive2 ------>AddReceiveUnit
    ambr::core::UnitHash last_unit_hash;
    ambr::core::Amount receive_amount;
    ambr::core::UnitHash receive_from_hash;
    ambr::core::Amount old_balance;

    EXPECT_TRUE(manager->GetLastUnitHashByPubKey(test_pub, last_unit_hash));
    std::list<ambr::core::UnitHash> wait_list = manager->GetWaitForReceiveList(test_pub);
    EXPECT_TRUE(wait_list.size() == 1);
    receive_from_hash = wait_list.front();
    EXPECT_TRUE(manager->GetSendAmount(receive_from_hash, receive_amount, &err));
    manager->GetBalanceByPubKey(test_pub, old_balance);

    std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::make_shared<ambr::core::ReceiveUnit>();

    receive_unit->set_version(0x00000001);
    receive_unit->set_type(ambr::core::UnitType::receive);
    receive_unit->set_public_key(test_pub);
    receive_unit->set_prev_unit(last_unit_hash);return;
    receive_unit->set_balance(old_balance+receive_amount);
    receive_unit->set_from(receive_from_hash);return;
    receive_unit->CalcHashAndFill();
    receive_unit->SignatureAndFill(test_pri);

    {//incorrect operate
      receive_unit->set_version(0x00000002);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_version(0x00000001);

      receive_unit->set_type(ambr::core::UnitType::send);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_type(ambr::core::UnitType::receive);

      receive_unit->set_public_key(test_pub+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_public_key(test_pub);

      receive_unit->set_prev_unit(last_unit_hash+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_prev_unit(last_unit_hash);

      receive_unit->set_balance(old_balance+receive_amount+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_balance(old_balance+receive_amount-1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_balance(old_balance+receive_amount);

      receive_unit->set_from(receive_from_hash-1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_from(receive_from_hash);

      receive_unit->set_hash(receive_unit->hash()+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->CalcHashAndFill();

      receive_unit->SignatureAndFill(test_pri+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->SignatureAndFill(test_pri);
    }
    EXPECT_TRUE(manager->AddReceiveUnit(receive_unit, &err));
  }
  {//test join validator set
    ambr::core::PrivateKey validator_pri[10];
    for(size_t i = 0; i < sizeof(validator_pri)/sizeof(ambr::core::PrivateKey); i++){
      validator_pri[i] = ambr::core::CreateRandomPrivateKey();
      EXPECT_TRUE(manager->SendToAddress(ambr::core::GetPublicKeyByPrivateKey(validator_pri[i]), 10000, root_pri_key, &test_hash, added_unit, &err));
      EXPECT_TRUE(manager->ReceiveFromUnitHash(test_hash, validator_pri[i], &test_hash, added_unit, &err));
    }
    EXPECT_TRUE(manager->JoinValidatorSet(test_pri, 10000, &test_hash, added_unit, &err));
  }
}
