/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_STORE_STORE_MANAGER_H_
#define AMBR_STORE_STORE_MANAGER_H_
#include <memory>
#include <list>
#include <core/unit.h>
#include <core/key.h>
#include <store/unit_store.h>
namespace rocksdb{
class DB;
class ColumnFamilyHandle;
class WriteBatch;
}

namespace ambr {
namespace store {

class StoreManager{
public:
  void Init();
  bool AddUnit(std::shared_ptr<core::Unit> unit, std::string* err);
  bool AddSendUnit(std::shared_ptr<core::SendUnit> send_unit, std::string* err);
  bool AddReceiveUnit(std::shared_ptr<core::ReceiveUnit> receive_unit, std::string* err);
  bool GetLastUnitHashByPubKey(const core::PublicKey& pub_key, core::UnitHash& hash);
  bool GetBalanceByPubKey(const core::PublicKey& pub_key, core::Amount& balance);
  std::list<std::shared_ptr<store::UnitStore>>
    GetTradeHistoryByPubKey(const core::PublicKey& pub_key, size_t count);
  bool GetSendAmount(const ambr::core::UnitHash &unit_hash, core::Amount& amount, std::string* err);

  bool SendToAddress(
      const core::PublicKey pub_key_to,
      const core::Amount& count,
      const core::PrivateKey& prv_key,
      core::UnitHash* tx_hash,
      std::string* err);
  bool ReceiveFromUnitHash(
      const core::UnitHash unit_hash,
      const core::PrivateKey& pri_key,
      core::UnitHash* tx_hash,
      std::string* err);
  std::list<core::UnitHash> GetWaitForReceiveList(const core::PublicKey& pub_key);

  std::shared_ptr<UnitStore> GetUnit(const core::UnitHash& hash);
  std::shared_ptr<SendUnitStore> GetSendUnit(const core::UnitHash& hash);
  std::shared_ptr<ReceiveUnitStore> GetReceiveUnit(const core::UnitHash& hash);
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
  StoreManager();
private:
  rocksdb::DB* db_unit_;
  rocksdb::ColumnFamilyHandle* handle_send_unit_;//unit_hash->SendUnitStore
  rocksdb::ColumnFamilyHandle* handle_receive_unit_;//unit_hash->ReceiveUnitStore
  rocksdb::ColumnFamilyHandle* handle_account_;//AcountPublicKey->LastUnitHash
  rocksdb::ColumnFamilyHandle* handle_wait_for_receive_;//AccountPublic->ReceiveList
};

inline std::shared_ptr<StoreManager> GetStoreManager(){
  return StoreManager::instance();
}

}
}
#endif
