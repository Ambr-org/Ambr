/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include "store_manager.h"
#include <memory>
#include <boost/filesystem.hpp>
#include <rocksdb/db.h>
#include <rocksdb/slice.h>
#include <rocksdb/options.h>
#include <core/key.h>
#include "unit_store.h"
static const int use_log = true;
std::shared_ptr<ambr::store::StoreManager> ambr::store::StoreManager::instance_ = std::shared_ptr<ambr::store::StoreManager>();
static const std::string init_addr = "ambr_y4bwxzwwrze3mt4i99n614njtsda6s658uqtue9ytjp7i5npg6pz47qdjhx3";
static const ambr::core::Amount init_balance=(boost::multiprecision::uint128_t)630000000000*1000;

//TODO: db sync
void ambr::store::StoreManager::Init(const std::string& path){

  rocksdb::DBOptions options;
  options.create_if_missing = true;
  options.create_missing_column_families = true;
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
  std::vector<rocksdb::ColumnFamilyHandle*> column_families_handle;

  column_families.push_back(rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("send_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("receive_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("account", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("handle_wait_for_receive", rocksdb::ColumnFamilyOptions()));
  rocksdb::Status status = rocksdb::DB::Open(options, path, column_families, &column_families_handle, &db_unit_);
  assert(status.ok());
  handle_send_unit_ = column_families_handle[0];
  handle_receive_unit_ = column_families_handle[1];
  handle_account_ = column_families_handle[2];
  handle_wait_for_receive_ = column_families_handle[3];

  {//first time init db
    core::Amount balance = core::Amount();
    core::PublicKey pub_key=ambr::core::GetPublicKeyByAddress(init_addr);

    if(!GetBalanceByPubKey(pub_key, balance)){
      std::shared_ptr<core::ReceiveUnit> unit = std::shared_ptr<core::ReceiveUnit>(new core::ReceiveUnit());

      //construct unit of genesis
      unit->set_version(0x00000001);
      unit->set_type(core::UnitType::receive);
      unit->set_public_key(pub_key);
      unit->set_prev_unit(core::UnitHash());
      unit->set_balance(init_balance);
      unit->set_sign(core::Signature());
      unit->set_from(core::Address());
      unit->CalcHashAndFill();


      //write genesis to database
      rocksdb::WriteBatch batch;
      std::shared_ptr<ReceiveUnitStore> rec_store = std::make_shared<ReceiveUnitStore>(unit);
      std::vector<uint8_t> bytes = rec_store->SerializeByte();
      std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = unit->hash().bytes();
      batch.Put(handle_receive_unit_,
                rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
                rocksdb::Slice((const char*)bytes.data(), bytes.size()));
      batch.Put(handle_account_,
                rocksdb::Slice((const char*)unit->public_key().bytes().data(), unit->public_key().bytes().size()),
                rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()));
      rocksdb::Status status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
      if(use_log){//TODO:use log
        std::cout<<"genesis create"<<std::endl;
        std::cout<<unit->hash().encode_to_hex()<<std::endl;
        std::cout<<rec_store->SerializeJson()<<std::endl;
      }
      assert(status.ok());
    }
  }
}

bool ambr::store::StoreManager::AddUnit(std::shared_ptr<ambr::core::Unit> unit, std::string *err){
  if(!unit){
    if(err)*err = "Unit ptr is null.";
    return false;
  }
  if(unit->type() == ambr::core::UnitType::send){
    //param check
    std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
    if(!send_unit){
      if(err)*err = "Unit cast to SendUnit error.";
      return false;
    }
    if(!send_unit->Validate(err)){
      return false;
    }
    //check account address
    {
      core::UnitHash hash;
      if(!GetLastUnitHashByPubKey(unit->public_key(), hash)){
        if(err){
          *err = "Con't find account address";
        }
        return false;
      }
    }
    //check balance
    {
      core::Amount balance;
      if(!GetBalanceByPubKey(send_unit->public_key(), balance)){
        if(err){
          *err = "Can't get balance count!";
        }
        return false;
      }
      if(send_unit->balance().data() >= balance.data()){
        if(err){
          *err = "Insufficient balance!";
        }
        return false;
      }
    }
    //write to db
    rocksdb::WriteBatch batch;
    std::vector<uint8_t> bytes = unit->SerializeByte();
    std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = send_unit->hash().bytes();
    batch.Put(handle_send_unit_, rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
              rocksdb::Slice((const char*)bytes.data(), bytes.size()));
    batch.Put(handle_account_, rocksdb::Slice((const char*)send_unit->public_key().bytes().data(), send_unit->public_key().bytes().size()),
              rocksdb::Slice((const char*)send_unit->hash().bytes().data(), send_unit->hash().bytes().size()));
    AddWaitForReceiveUnit(send_unit->dest(), send_unit->hash(), &batch);

    if(use_log){//TODO:use log module
      std::cout<<"Add unit for send!"<<std::endl;
      std::cout<<unit->hash().encode_to_hex()<<std::endl;
      std::cout<<unit->SerializeJson()<<std::endl;
      std::cout<<"address:"<<ambr::core::GetAddressStringByPublicKey(send_unit->public_key())
              <<"'s last unit change to "<<send_unit->hash().encode_to_hex();
    }
    rocksdb::Status status = db_unit_->Write(rocksdb::WriteOptions(), &batch);

    assert(status.ok());
    return true;
  }else if(unit->type() == ambr::core::UnitType::receive){
    std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
    if(!receive_unit){
      if(err)*err = "Unit cast to ReceiveUnit error.";
      return false;
    }
    if(!receive_unit->Validate(err)){
      return false;
    }
    //chain check
    //TODO:
    //write to db
    rocksdb::WriteBatch batch;
    std::vector<uint8_t> bytes = unit->SerializeByte();
    std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = receive_unit->hash().bytes();
    batch.Put(handle_receive_unit_, rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
              rocksdb::Slice((const char*)bytes.data(), bytes.size()));
    batch.Put(handle_account_, ambr::core::GetAddressStringByPublicKey(receive_unit->public_key()),
              rocksdb::Slice((const char*)receive_unit->hash().bytes().data(), receive_unit->hash().bytes().size()));
    rocksdb::Status status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
    assert(status.ok());
    return true;
  }
  else{
    if(err)*err = "Unit type is error.";
    return false;
  }
  return true;
}

bool ambr::store::StoreManager::AddSendUnit(std::shared_ptr<ambr::core::SendUnit> send_unit, std::string *err){
  if(!send_unit){
    if(err)*err = "Unit cast to SendUnit error.";
    return false;
  }
  if(!send_unit->Validate(err)){
    return false;
  }
  //check account address
  {
    core::UnitHash hash;
    if(!GetLastUnitHashByPubKey(send_unit->public_key(), hash)){
      if(err){
        *err = "Con't find account address";
      }
      return false;
    }
  }
  //check balance
  {
    core::Amount balance;
    if(!GetBalanceByPubKey(send_unit->public_key(), balance)){
      if(err){
        *err = "Can't get balance count!";
      }
      return false;
    }
    if(send_unit->balance().data() >= balance.data()){
      if(err){
        *err = "Insufficient balance!";
      }
      return false;
    }
  }
  //write to db
  std::shared_ptr<SendUnitStore> store = std::make_shared<SendUnitStore>(send_unit);
  rocksdb::WriteBatch batch;
  std::vector<uint8_t> bytes = store->SerializeByte();
  std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = send_unit->hash().bytes();
  batch.Put(handle_send_unit_, rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
            rocksdb::Slice((const char*)bytes.data(), bytes.size()));
  batch.Put(handle_account_, rocksdb::Slice((const char*)send_unit->public_key().bytes().data(), send_unit->public_key().bytes().size()),
            rocksdb::Slice((const char*)send_unit->hash().bytes().data(), send_unit->hash().bytes().size()));
  AddWaitForReceiveUnit(send_unit->dest(), send_unit->hash(), &batch);
  if(use_log){//TODO:use log module
    std::cout<<"Add unit for send!"<<std::endl;
    std::cout<<send_unit->hash().encode_to_hex()<<std::endl;
    std::cout<<store->SerializeJson()<<std::endl;
    std::cout<<"address:"<<ambr::core::GetAddressStringByPublicKey(send_unit->public_key())
            <<"'s last unit change to "<<send_unit->hash().encode_to_hex();
  }
  rocksdb::Status status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
  assert(status.ok());
  return true;
}

bool ambr::store::StoreManager::AddReceiveUnit(std::shared_ptr<ambr::core::ReceiveUnit> receive_unit, std::string *err){
  if(!receive_unit){
    if(err)*err = "receive_unit is nullptr.";
    return false;
  }
  if(!receive_unit->Validate(err)){
    if(err)*err = "receive_unit  is invalidate.";
    return false;
  }

  //chain check
  std::shared_ptr<SendUnitStore> send_unit_store = GetSendUnit(receive_unit->from());
  if(!send_unit_store){
    if(err)*err = "Con't find send unit store.";
    return false;
  }

  //check receive member
  if(send_unit_store->unit()->dest() != receive_unit->public_key()){
    if(err)*err = "This receiver is not right.";
    return false;
  }

  //check receive count
  core::Amount balance_old;
  std::shared_ptr<store::UnitStore> prev_receive_store = GetUnit(receive_unit->prev_unit());
  if(prev_receive_store){
    balance_old.set_data(receive_unit->balance().data()-prev_receive_store->GetUnit()->balance().data());
  }else{
    balance_old.set_data(receive_unit->balance().data());
  }
  std::shared_ptr<store::UnitStore> prev_send_store = GetUnit(send_unit_store->unit()->prev_unit());
  assert(prev_send_store);
  if(balance_old.data() !=
      prev_send_store->GetUnit()->balance().data()-send_unit_store->GetUnit()->balance().data()){
    if(err)*err = "Error balance number.";
    return false;
  }
  rocksdb::WriteBatch batch;
  auto receive_unit_store = std::make_shared<ReceiveUnitStore>(receive_unit);
  std::vector<uint8_t> bytes = receive_unit_store->SerializeByte();
  std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = receive_unit->hash().bytes();
  batch.Put(handle_receive_unit_, rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
            rocksdb::Slice((const char*)bytes.data(), bytes.size()));
  batch.Put(handle_account_, rocksdb::Slice((const char*)receive_unit->public_key().bytes().data(), receive_unit->public_key().bytes().size()),
            rocksdb::Slice((const char*)receive_unit->hash().bytes().data(), receive_unit->hash().bytes().size()));
  send_unit_store->set_receive_unit_hash(receive_unit->hash());
  bytes = send_unit_store->SerializeByte();
  batch.Put(handle_send_unit_, rocksdb::Slice((const char*)send_unit_store->unit()->hash().bytes().begin(), send_unit_store->unit()->hash().bytes().size()),
            rocksdb::Slice((const char*)bytes.data(), bytes.size()));
  RemoveWaitForReceiveUnit(receive_unit->public_key(), receive_unit->from(), &batch);
  rocksdb::Status status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
  assert(status.ok());
  return true;
}

bool ambr::store::StoreManager::GetLastUnitHashByPubKey(const ambr::core::PublicKey &pub_key, ambr::core::UnitHash& hash){
  std::string value_get;
  rocksdb::Status status = db_unit_->Get(rocksdb::ReadOptions(), handle_account_, rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()), &value_get);
  if(status.IsNotFound()){
    return false;
  }
  assert(status.ok());
  hash.set_bytes(value_get.data(), value_get.size());
  return true;
}

bool ambr::store::StoreManager::GetBalanceByPubKey(const ambr::core::PublicKey &pub_key, core::Amount &balance){
  ambr::core::UnitHash hash;
  if(GetLastUnitHashByPubKey(pub_key, hash)){
    std::shared_ptr<UnitStore> store = GetUnit(hash);
    if(store->type() == UnitStore::ST_SendUnit){
      std::shared_ptr<SendUnitStore> send_store = std::dynamic_pointer_cast<SendUnitStore>(store);
      if(!send_store){
        return false;
      }
      balance = send_store->unit()->balance();
      return true;
    }else if(store->type() == UnitStore::ST_ReceiveUnit){
      std::shared_ptr<ReceiveUnitStore> receive_store = std::dynamic_pointer_cast<ReceiveUnitStore>(store);
      if(!receive_store){
        return false;
      }
      balance = receive_store->unit()->balance();
      return true;
    }
  }
  return false;
}

std::list<std::shared_ptr<ambr::store::UnitStore> > ambr::store::StoreManager::GetTradeHistoryByPubKey(const ambr::core::PublicKey &pub_key, size_t count){
  std::list<std::shared_ptr<ambr::store::UnitStore> > unit_list;
  ambr::core::UnitHash hash_iter;
  std::shared_ptr<ambr::store::UnitStore> unit_ptr;

  size_t count_idx = 0;
  if(GetLastUnitHashByPubKey(pub_key, hash_iter)){
    while(unit_ptr = GetUnit(hash_iter)){
      count_idx++;
      if(count_idx > count || count_idx >1000){
        break;
      }
      unit_list.push_back(unit_ptr);
      hash_iter = unit_ptr->GetUnit()->prev_unit();
    }
  }
  return unit_list;
}

bool ambr::store::StoreManager::GetSendAmount(const ambr::core::UnitHash &unit_hash, ambr::core::Amount &amount, std::string *err)
{
  core::Amount balance_send;
  std::shared_ptr<SendUnitStore> send_store = GetSendUnit(unit_hash);
  if(!send_store){
    if(err)*err = "con't find send unit.";
    return false;
  }
  balance_send = send_store->unit()->balance();

  core::Amount balance_send_pre;
  std::shared_ptr<UnitStore> store_pre = GetUnit(send_store->unit()->prev_unit());
  if(!store_pre){
    if(err)*err = "con't find send unit's pre unit.";
    return false;
  }
  balance_send_pre = store_pre->GetUnit()->balance();
  amount.set_data(balance_send_pre.data()-balance_send.data());
  return true;
}



bool ambr::store::StoreManager::SendToAddress(
    const ambr::core::PublicKey pub_key_to,
    const ambr::core::Amount &send_count,
    const ambr::core::PrivateKey &prv_key,
    core::UnitHash* tx_hash,
    std::shared_ptr<ambr::core::Unit>& unit_sended,
    std::string* err){
  std::shared_ptr<core::SendUnit> unit = std::shared_ptr<core::SendUnit>(new core::SendUnit());
  core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(prv_key);
  core::UnitHash prev_hash;
  if(!GetLastUnitHashByPubKey(pub_key, prev_hash)){
    if(err){
      *err = "Can't find sender's last unithash";
    }
    return false;
  }
  core::Amount balance;
  if(!GetBalanceByPubKey(pub_key, balance)){
    if(err){
      *err = "Can't find sender's balance";
    }
    return false;
  }
  if(balance < send_count){
    if(err){
      *err = "Insufficient balance!";
    }
    return false;
  }
  balance.set_data(balance.data() -send_count.data());
  unit->set_version(0x00000001);
  unit->set_type(core::UnitType::send);
  unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(prv_key));
  unit->set_prev_unit(prev_hash);
  unit->set_balance(balance);
  unit->set_dest(pub_key_to);
  unit->CalcHashAndFill();
  unit->SignatureAndFill(prv_key);
  unit_sended = unit;
  if(tx_hash)*tx_hash = unit->hash();
  return AddSendUnit(unit, err);
}

bool ambr::store::StoreManager::ReceiveFromUnitHash(
    const core::UnitHash unit_hash,
    const ambr::core::PrivateKey &pri_key,
    core::UnitHash* tx_hash,
    std::shared_ptr<ambr::core::Unit>& unit_received,
    std::string *err){
  std::shared_ptr<core::ReceiveUnit> unit = std::shared_ptr<core::ReceiveUnit>(new core::ReceiveUnit());
  core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(pri_key);
  core::UnitHash prev_hash;
  if(!GetLastUnitHashByPubKey(pub_key, prev_hash)){
    prev_hash.clear();
  }
  core::Amount balance;
  if(!GetBalanceByPubKey(pub_key, balance)){
    balance.clear();
  }
  //TODO use GetSendAmount
  core::Amount balance_send;
  std::shared_ptr<SendUnitStore> send_store = GetSendUnit(unit_hash);
  if(!send_store){
    if(err)*err = "con't find send unit.";
    return false;
  }
  balance_send = send_store->unit()->balance();

  core::Amount balance_send_pre;
  std::shared_ptr<UnitStore> store_pre = GetUnit(send_store->unit()->prev_unit());
  if(!store_pre){
    if(err)*err = "con't find send unit's pre unit.";
    return false;
  }
  balance_send_pre = store_pre->GetUnit()->balance();

  balance.set_data(balance.data()+(balance_send_pre.data()-balance_send.data()));

  unit->set_version(0x00000001);
  unit->set_type(core::UnitType::receive);
  unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(pri_key));
  unit->set_prev_unit(prev_hash);
  unit->set_balance(balance);
  unit->set_from(unit_hash);
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);
  unit_received = unit;
  if(tx_hash)*tx_hash = unit->hash();
  return AddReceiveUnit(unit, err);
}

std::list<ambr::core::UnitHash> ambr::store::StoreManager::GetWaitForReceiveList(const ambr::core::PublicKey &pub_key){
  //TODO Improve efficiency
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                               rocksdb::ReadOptions(),
                               handle_wait_for_receive_,
                               rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()),
                               &string_readed);
  if(!status.IsNotFound()){
    assert(status.ok());
  }
  size_t idx = 0;
  std::list<ambr::core::UnitHash> rtn;
  while(idx+sizeof(core::UnitHash) <= string_readed.size()){
    //std::array<uint8_t, sizeof(core::UnitHash)> xxx = *(std::array<uint8_t, sizeof(core::UnitHash)>*)(string_readed.data()+idx);
    rtn.push_back(core::UnitHash(*(std::array<uint8_t, sizeof(core::UnitHash)>*)(string_readed.data()+idx)));
    idx += sizeof(core::UnitHash);
  }
  return rtn;
}

std::shared_ptr<ambr::store::UnitStore> ambr::store::StoreManager::GetUnit(const ambr::core::UnitHash &hash){
  std::shared_ptr<ambr::store::SendUnitStore> send_unit = GetSendUnit(hash);
  if(send_unit){
    return send_unit;
  }else{
    std::shared_ptr<ambr::store::ReceiveUnitStore> receive_unit = GetReceiveUnit(hash);
    if(receive_unit){
      return receive_unit;
    }
  }
  return nullptr;
}

std::shared_ptr<ambr::store::SendUnitStore> ambr::store::StoreManager::GetSendUnit(const ambr::core::UnitHash &hash){
  std::shared_ptr<ambr::store::SendUnitStore> rtn;
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                                      rocksdb::ReadOptions(),
                                      handle_send_unit_,
                                      rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                                      &string_readed);
  if(status.IsNotFound()){
    return rtn;
  }
  assert(status.ok());
  rtn = std::make_shared<ambr::store::SendUnitStore>(nullptr);
  if(rtn->DeSerializeByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()))){
    return rtn;
  }
  return std::shared_ptr<ambr::store::SendUnitStore>();
}

std::shared_ptr<ambr::store::ReceiveUnitStore> ambr::store::StoreManager::GetReceiveUnit(const ambr::core::UnitHash &hash){
  std::shared_ptr<ambr::store::ReceiveUnitStore> rtn;
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                                      rocksdb::ReadOptions(),
                                      handle_receive_unit_,
                                      rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                                      &string_readed);
  if(status.IsNotFound()){
    return rtn;
  }
  assert(status.ok());
  rtn = std::make_shared<ambr::store::ReceiveUnitStore>(nullptr);
  if(rtn->DeSerializeByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()))){
    return rtn;
  }
  return std::shared_ptr<ambr::store::ReceiveUnitStore>();
}

std::list<ambr::core::UnitHash> ambr::store::StoreManager::GetAccountListFromAccountForDebug(){
  std::list<ambr::core::UnitHash> rtn_list;
  rocksdb::Iterator* it = db_unit_->NewIterator(rocksdb::ReadOptions(), handle_account_);
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    assert(it->status().ok());
    ambr::core::UnitHash hash;
    hash.set_bytes(it->key().data(), it->key().size());
    rtn_list.push_back(hash);
  }
  return rtn_list;
}

std::list<ambr::core::UnitHash> ambr::store::StoreManager::GetAccountListFromWaitForReceiveForDebug(){
  std::list<ambr::core::UnitHash> rtn_list;
  rocksdb::Iterator* it = db_unit_->NewIterator(rocksdb::ReadOptions(), handle_wait_for_receive_);
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    assert(it->status().ok());
    ambr::core::UnitHash hash;
    hash.set_bytes(it->key().data(), it->key().size());
    rtn_list.push_back(hash);
  }
  return rtn_list;
}

void ambr::store::StoreManager::AddWaitForReceiveUnit(const ambr::core::PublicKey &pub_key, const ambr::core::UnitHash &hash, rocksdb::WriteBatch* batch){
  //TODO Improve efficiency
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                               rocksdb::ReadOptions(),
                               handle_wait_for_receive_,
                               rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()),
                               &string_readed);
  if(!status.IsNotFound()){
    assert(status.ok());
  }
  std::vector<uint8_t> vec_for_write(string_readed.begin(), string_readed.end());
  vec_for_write.insert(vec_for_write.end(), hash.bytes().begin(), hash.bytes().end());
  if(batch){
    status = batch->Put(handle_wait_for_receive_,
                        rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()),
                        rocksdb::Slice((const char*)vec_for_write.data(), vec_for_write.size()));
  }else{
    status = db_unit_->Put(rocksdb::WriteOptions(),
                           handle_wait_for_receive_,
                           rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()),
                           rocksdb::Slice((const char*)vec_for_write.data(), vec_for_write.size()));
  }
  assert(status.ok());
}
void ambr::store::StoreManager::RemoveWaitForReceiveUnit(const ambr::core::PublicKey &pub_key, const ambr::core::UnitHash &hash, rocksdb::WriteBatch *batch){
  std::list<core::UnitHash> hash_list = GetWaitForReceiveList(pub_key);
  hash_list.remove(hash);
  std::vector<uint8_t> vec_for_write;
  for(std::list<core::UnitHash>::iterator iter = hash_list.begin(); iter != hash_list.end(); iter++){
    vec_for_write.insert(vec_for_write.end(), iter->bytes().begin(), iter->bytes().end());
  }
  rocksdb::Status status;
  if(batch){
    status = batch->Put(handle_wait_for_receive_,
                        rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()),
                        rocksdb::Slice((const char*)vec_for_write.data(), vec_for_write.size()));
  }else{
    status = db_unit_->Put(rocksdb::WriteOptions(),
                           handle_wait_for_receive_,
                           rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()),
                           rocksdb::Slice((const char*)vec_for_write.data(), vec_for_write.size()));
  }
}

ambr::store::StoreManager::StoreManager(){
  //Init();
}


