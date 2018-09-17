/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_STORE_STORE_MANAGER_H_
#define AMBR_STORE_STORE_MANAGER_H_
#include <memory>
#include <list>
#include <unordered_map>
#include <boost/signals2.hpp>
#include <core/unit.h>
#include <core/key.h>
#include <store/unit_store.h>
#include <thread>
#include <mutex>

typedef std::lock_guard<std::recursive_mutex> LockGrade;
namespace rocksdb{
class DB;
class ColumnFamilyHandle;
class WriteBatch;
}

namespace ambr {
namespace store {


class StoreManager{
public:
  StoreManager();
  ~StoreManager();
public:
  void Init(const std::string& path);
  //callback
  boost::signals2::connection AddCallBackReceiveNewSendUnit(std::function<void(std::shared_ptr<core::SendUnit>)> callback);
  boost::signals2::connection AddCallBackReceiveNewReceiveUnit(std::function<void(std::shared_ptr<core::ReceiveUnit>)> callback);
  boost::signals2::connection AddCallBackReceiveNewJoinValidatorSetUnit(std::function<void(std::shared_ptr<core::EnterValidateSetUint>)> callback);
  boost::signals2::connection AddCallBackReceiveNewLeaveValidatorSetUnit(std::function<void(std::shared_ptr<core::LeaveValidateSetUint>)> callback);
  boost::signals2::connection AddCallBackReceiveNewValidatorUnit(std::function<void(std::shared_ptr<core::ValidatorUnit>)> callback);
  boost::signals2::connection AddCallBackReceiveNewVoteUnit(std::function<void(std::shared_ptr<core::VoteUnit>)> callback);
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
  bool GetSendAmountWithTransactionFee(const ambr::core::UnitHash &unit_hash, core::Amount& amount, std::string* err);
  bool GetReceiveAmount(const ambr::core::UnitHash &unit_hash, core::Amount& amount, std::string* err);
  //get all new unit map at lastest of account  which is not validated by validator set
  std::unordered_map<ambr::core::PublicKey, ambr::core::UnitHash>
    GetNewUnitMap();
  std::shared_ptr<store::ValidatorSetStore> GetValidatorSet();
  bool SendToAddressWithContract(
      const core::PublicKey pub_key_to,
      const core::Amount& count,
      const core::PrivateKey& prv_key,
      core::SendUnit::DataType data_type,
      const std::string& data,
      core::UnitHash* tx_hash,
      std::shared_ptr<ambr::core::Unit>& unit_sended,
      std::string* err);
  bool SendToAddress(
      const core::PublicKey pub_key_to,
      const core::Amount& count,
      const core::PrivateKey& prv_key,
      core::UnitHash* tx_hash,
      std::shared_ptr<ambr::core::Unit>& unit_sended,
      std::string* err);
  bool SendMessage(
      const core::PrivateKey& prv_key,
      const std::string& message,
      core::UnitHash* tx_hash,
      std::shared_ptr<ambr::core::Unit>& unit_sended,
      std::string* err);
  bool SendContract(
      const core::PrivateKey& prv_key,
      core::SendUnit::DataType data_type,
      const std::string& data,
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
  std::shared_ptr<ValidatorUnitStore> GetValidateUnit(const core::UnitHash& hash);
  std::shared_ptr<ValidatorUnitStore> GetLastestValidateUnit();
  std::shared_ptr<EnterValidatorSetUnitStore> GetEnterValidatorSetUnit(const core::UnitHash& hash);
  std::shared_ptr<LeaveValidatorSetUnitStore> GetLeaveValidatorSetUnit(const core::UnitHash& hash);
  std::list<std::shared_ptr<core::VoteUnit>> GetVoteList();
public:
  //could rm not final confirmation unit
  //all unit that depend on this unit will be removed too.
  bool RemoveUnit(const core::UnitHash& hash, std::string* err);
public:
  uint64_t GetGenesisTime(){return genesis_time_;}
  void SetValidateUnitInterval(uint32_t interval){ validate_unit_interval_ = interval;}
  uint32_t GetValidateUnitInterval(){return validate_unit_interval_;}
  uint64_t GetPassPercent(){return PASS_PERCENT;}
  uint64_t GetNonceByNowTime();
  std::recursive_mutex& GetMutex(){return mutex_;}
  static uint64_t GetTransectionFeeBase(){return 1;};
  static const ambr::core::Amount GetMinValidatorBalance() { return (boost::multiprecision::uint128_t)100000000*1000;};
  uint64_t GetTransectionFeeCountWhenReceive(std::shared_ptr<core::Unit> send_unit);
public://for debug
  std::list<core::UnitHash> GetAccountListFromAccountForDebug();
  std::list<core::UnitHash> GetAccountListFromWaitForReceiveForDebug();
public:
  static std::shared_ptr<StoreManager> instance(){
    if(!instance_)
      instance_ = std::shared_ptr<StoreManager>(new StoreManager());
    return instance_;
  }
private:

  //if batch == 0 writedb without batch
  void AddWaitForReceiveUnit(const core::PublicKey& pub_key, const core::UnitHash& hash, rocksdb::WriteBatch* batch);
  void RemoveWaitForReceiveUnit(const core::PublicKey& pub_key, const core::UnitHash& hash, rocksdb::WriteBatch* batch);
private:
  static std::shared_ptr<StoreManager> instance_;

private:
  rocksdb::DB* db_unit_;
  rocksdb::ColumnFamilyHandle* handle_send_unit_;//unit_hash->SendUnitStore
  rocksdb::ColumnFamilyHandle* handle_receive_unit_;//unit_hash->ReceiveUnitStore
  rocksdb::ColumnFamilyHandle* handle_account_;//AccoutPublicKey->LastUnitHash
  rocksdb::ColumnFamilyHandle* handle_new_account_;//AccoutPublic(not validated by validator set)->last unit hash
  rocksdb::ColumnFamilyHandle* handle_wait_for_receive_;//AccountPublic->ReceiveList
  rocksdb::ColumnFamilyHandle* handle_validator_unit_;//unit_hash->validate unit
  rocksdb::ColumnFamilyHandle* handle_enter_validator_unit_;//unit_hash->EnterValidatorUnitStore
  rocksdb::ColumnFamilyHandle* handle_leave_validator_unit_;//unit_hash->LeaveValidatorUnitStore
  rocksdb::ColumnFamilyHandle* handle_validator_set_;//unit_hash->validator_set
  std::list<std::shared_ptr<core::VoteUnit>> vote_list_;
  const uint64_t PERCENT_MAX=10000u;
  const uint64_t PASS_PERCENT=10000u*7/10;
  uint64_t genesis_time_;
  uint32_t validate_unit_interval_ = 3000u;//2s
  std::recursive_mutex mutex_;
private:
  boost::signals2::signal<void(std::shared_ptr<core::SendUnit>)> DoReceiveNewSendUnit;
  boost::signals2::signal<void(std::shared_ptr<core::ReceiveUnit>)> DoReceiveNewReceiveUnit;
  boost::signals2::signal<void(std::shared_ptr<core::EnterValidateSetUint>)> DoReceiveNewEnterValidateSetUnit;
  boost::signals2::signal<void(std::shared_ptr<core::LeaveValidateSetUint>)> DoReceiveNewLeaveValidateSetUnit;
  boost::signals2::signal<void(std::shared_ptr<core::ValidatorUnit>)> DoReceiveNewValidatorUnit;
  boost::signals2::signal<void(std::shared_ptr<core::VoteUnit>)> DoReceiveNewVoteUnit;
};
}
}
#endif
