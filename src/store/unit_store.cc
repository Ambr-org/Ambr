/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include "unit_store.h"
#include <memory>
#include <boost/filesystem.hpp>
#include <rocksdb/db.h>
#include <rocksdb/slice.h>
#include <rocksdb/options.h>
#include <core/key.h>
static const int use_log = true;
std::shared_ptr<ambr::store::UnitStore> ambr::store::UnitStore::instance_ = std::shared_ptr<ambr::store::UnitStore>();
static const std::string init_addr = "ambr_179omdinczkoprf4cij8o6dx5bbk9mpoptqndm37e7sxdasz1ijsc8b4yab3";
static const ambr::core::Amount init_balance=(boost::multiprecision::uint128_t)630000000000*1000;

//TODO: db sync
namespace test_temp{


}
void ambr::store::UnitStore::Init(){

  rocksdb::DBOptions options;
  options.create_if_missing = true;
  options.create_missing_column_families = true;
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
  std::vector<rocksdb::ColumnFamilyHandle*> column_families_handle;

  column_families.push_back(rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("send_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("receive_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("account", rocksdb::ColumnFamilyOptions()));

  rocksdb::Status status = rocksdb::DB::Open(options, "./unit.db", column_families, &column_families_handle, &db_unit_);
  assert(status.ok());
  handle_send_unit_ = column_families_handle[0];
  handle_receive_unit_ = column_families_handle[1];
  handle_account_ = column_families_handle[2];

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
      std::vector<uint8_t> bytes = unit->SerializeByte();
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
        std::cout<<unit->SerializeJson()<<std::endl;
      }
      assert(status.ok());
    }
  }
}

bool ambr::store::UnitStore::AddUnit(std::shared_ptr<ambr::core::Unit> unit, std::string *err){
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

bool ambr::store::UnitStore::GetLastUnitHashByPubKey(const ambr::core::PublicKey &pub_key, ambr::core::UnitHash& hash){
  std::string value_get;
  rocksdb::Status status = db_unit_->Get(rocksdb::ReadOptions(), handle_account_, rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()), &value_get);
  if(status.IsNotFound()){
    return false;
  }
  assert(status.ok());
  hash.set_bytes(value_get.data(), value_get.size());
  return true;
}

bool ambr::store::UnitStore::GetBalanceByPubKey(const ambr::core::PublicKey &pub_key, core::Amount &balance){
  ambr::core::UnitHash hash;
  if(GetLastUnitHashByPubKey(pub_key, hash)){
    std::shared_ptr<core::Unit> unit = GetUnit(hash);
    if(unit){
      balance = unit->balance();
      return true;
    }
  }
  return false;
}

std::list<std::shared_ptr<ambr::core::Unit> > ambr::store::UnitStore::GetTradeHistoryByPubKey(const ambr::core::PublicKey &pub_key, size_t count){
  std::list<std::shared_ptr<ambr::core::Unit> > unit_list;
  ambr::core::UnitHash hash_iter;
  std::shared_ptr<ambr::core::Unit> unit_ptr;
  while(GetLastUnitHashByPubKey(pub_key, hash_iter) && (unit_ptr = GetUnit(hash_iter))){
    unit_list.push_back(unit_ptr);
  }
  return unit_list;
}

bool ambr::store::UnitStore::SendToAddress(
    const ambr::core::PublicKey pub_key_to,
    const ambr::core::Amount &send_count,
    const ambr::core::PrivateKey &prv_key,
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
  unit->set_sign(core::Signature());
  unit->set_dest(pub_key_to);
  unit->CalcHashAndFill();
  return AddUnit(unit, err);
}

std::shared_ptr<ambr::core::Unit> ambr::store::UnitStore::GetUnit(const ambr::core::UnitHash &hash){
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                             rocksdb::ReadOptions(),
                             handle_receive_unit_,
                             rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                             &string_readed);
  if(status.IsNotFound()){
    status = db_unit_->Get(
                                 rocksdb::ReadOptions(),
                                 handle_send_unit_,
                                 rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                                 &string_readed);
    if(status.IsNotFound()){
      return std::shared_ptr<ambr::core::Unit>();
    }
  }
  assert(status.ok());
  return ambr::core::Unit::CreateUnitByByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()));
}

ambr::store::UnitStore::UnitStore(){
  Init();
}


