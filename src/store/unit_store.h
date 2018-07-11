/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_STORE_UNIT_STORE_H_
#define AMBR_STORE_UNIT_STORE_H_
#include <memory>
#include <list>
#include <core/unit.h>
#include <core/key.h>

namespace rocksdb{
class DB;
class ColumnFamilyHandle;
}
namespace test_temp{
ambr::core::PublicKey GetPublicKeyByPrivateKey(const ambr::core::PrivateKey& pri_key);
std::string GetAddressByPublicKey(const ambr::core::PublicKey& pub_key);
//std::string GetStringAddressByPublicKey(const ambr::core::PublicKey& pub_key);
std::string GetAddressByPrivateKey(const ambr::core::PrivateKey &pri_key);
bool AddressIsValidate(const std::string& addr);
ambr::core::PublicKey GetPublicKeyByAddress(const std::string& addr);
}
namespace ambr {
namespace store {

class UnitStore{
public:
  void Init();
  bool AddUnit(std::shared_ptr<core::Unit> unit, std::string* err);
  bool GetLastUnitHashByPubKey(const core::PublicKey& pub_key, core::UnitHash& hash);
  bool GetBalanceByPubKey(const core::PublicKey& pub_key, core::Amount& balance);
  std::list<std::shared_ptr<core::Unit>>
    GetTradeHistoryByPubKey(const core::PublicKey& pub_key, size_t count);

  bool SendToAddress(
      const core::PublicKey pub_key_to,
      const core::Amount& count,
      const core::PrivateKey& prv_key,
      std::string* err);
public:
  static std::shared_ptr<UnitStore> instance(){
    if(!instance_)
      instance_ = std::shared_ptr<UnitStore>(new UnitStore());
    return instance_;
  }
private:
  std::shared_ptr<core::Unit> GetUnit(const core::UnitHash& hash);
private:
  static std::shared_ptr<UnitStore> instance_;
  UnitStore();
private:
  rocksdb::DB* db_unit_;
  rocksdb::ColumnFamilyHandle* handle_send_unit_;
  rocksdb::ColumnFamilyHandle* handle_receive_unit_;
  rocksdb::ColumnFamilyHandle* handle_account_;
};

inline std::shared_ptr<UnitStore> GetUnitStore(){
  return UnitStore::instance();
}

}
}
#endif
