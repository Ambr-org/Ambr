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

  bool SendToAddress(
      const core::PublicKey pub_key_to,
      const core::Amount& count,
      const core::PrivateKey& prv_key,
      std::string* err);
public:
  static std::shared_ptr<StoreManager> instance(){
    if(!instance_)
      instance_ = std::shared_ptr<StoreManager>(new StoreManager());
    return instance_;
  }
private:
  std::shared_ptr<UnitStore> GetUnit(const core::UnitHash& hash);
private:
  static std::shared_ptr<StoreManager> instance_;
  StoreManager();
private:
  rocksdb::DB* db_unit_;
  rocksdb::ColumnFamilyHandle* handle_send_unit_;
  rocksdb::ColumnFamilyHandle* handle_receive_unit_;
  rocksdb::ColumnFamilyHandle* handle_account_;
};

inline std::shared_ptr<StoreManager> GetStoreManager(){
  return StoreManager::instance();
}

}
}
#endif
