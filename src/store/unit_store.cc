#include "unit_store.h"
#include <memory>
#include <boost/filesystem.hpp>
#include <leveldb/db.h>
#include <leveldb/options.h>
#include <leveldb/write_batch.h>

#include <core/key.h>
static const int use_log = true;
std::shared_ptr<ambr::store::UnitStore> ambr::store::UnitStore::instance_ = std::shared_ptr<ambr::store::UnitStore>();
static const std::string init_addr = "1234567890123456789012345678901234567890123456789012345678901234";
static const ambr::core::Amount init_balance=(boost::multiprecision::uint128_t)630000000000*1000;


namespace test_temp{
ambr::core::PublicKey GetPublicKeyByPrivateKey(const ambr::core::PrivateKey& pri_key){
  return ambr::core::PublicKey(pri_key);
}
std::string GetAddressByPublicKey(const ambr::core::PublicKey& pub_key){
  return pub_key.encode_to_hex();
}

std::string GetAddressByPrivateKey(const ambr::core::PrivateKey &pri_key){
  return GetAddressByPublicKey(GetPublicKeyByPrivateKey(pri_key));
}
ambr::core::PublicKey GetPublicKeyByAddress(const std::string& addr){
  return ambr::core::PublicKey(addr);
}
bool AddressIsValidate(const std::string& addr){
  return true;
}
}
void ambr::store::UnitStore::Init(){  
  leveldb::Options options;
  options.create_if_missing = true;
  leveldb::Status status = leveldb::DB::Open(options, "./unit.db", &db_unit_);
  assert(status.ok());
  {//first time init db
    core::Amount balance = core::Amount();
    core::PublicKey pub_key=test_temp::GetPublicKeyByAddress(init_addr);

    if(!GetBalanceByPubKey(pub_key, balance)){
      std::shared_ptr<core::ReceiveUnit> unit = std::shared_ptr<core::ReceiveUnit>(new core::ReceiveUnit());

      //construct unit of genesis
      unit->set_version(0x00000001);
      unit->set_type(core::UnitType::receive);
      unit->set_public_key(core::PublicKey());
      unit->set_prev_unit(core::UnitHash());
      unit->set_balance(init_balance);
      unit->set_sign(core::Signature());
      unit->set_from(core::Address());
      unit->CalcHashAndFill();

      //write genesis to database
      leveldb::WriteBatch batch;
      std::vector<uint8_t> bytes = unit->SerializeByte();
      std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = unit->hash().bytes();
      batch.Put(leveldb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
                leveldb::Slice((const char*)bytes.data(), bytes.size()));
      batch.Put(init_addr,
                leveldb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()));
      leveldb::Status status = db_unit_->Write(leveldb::WriteOptions(), &batch);
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
    leveldb::WriteBatch batch;
    std::vector<uint8_t> bytes = unit->SerializeByte();
    std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = send_unit->hash().bytes();
    batch.Put(leveldb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
              leveldb::Slice((const char*)bytes.data(), bytes.size()));
    batch.Put(test_temp::GetAddressByPublicKey(send_unit->public_key()),
              leveldb::Slice((const char*)send_unit->hash().bytes().data(), send_unit->hash().bytes().size()));
    if(use_log){//TODO:use log module
      std::cout<<"Add unit for send!"<<std::endl;
      std::cout<<unit->hash().encode_to_hex()<<std::endl;
      std::cout<<unit->SerializeJson()<<std::endl;
      std::cout<<"address:"<<test_temp::GetAddressByPublicKey(send_unit->public_key())
              <<"'s last unit change to "<<send_unit->hash().encode_to_hex();
    }
    leveldb::Status status = db_unit_->Write(leveldb::WriteOptions(), &batch);
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
    leveldb::WriteBatch batch;
    std::vector<uint8_t> bytes = unit->SerializeByte();
    std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = receive_unit->hash().bytes();
    batch.Put(leveldb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
              leveldb::Slice((const char*)bytes.data(), bytes.size()));
    batch.Put(test_temp::GetAddressByPublicKey(receive_unit->public_key()),
              leveldb::Slice((const char*)receive_unit->hash().bytes().data(), receive_unit->hash().bytes().size()));
    leveldb::Status status = db_unit_->Write(leveldb::WriteOptions(), &batch);
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
  leveldb::Status status = db_unit_->Get(leveldb::ReadOptions(), test_temp::GetAddressByPublicKey(pub_key), &value_get);
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
  core::PublicKey pub_key = test_temp::GetPublicKeyByPrivateKey(prv_key);
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
  unit->set_public_key(test_temp::GetPublicKeyByPrivateKey(prv_key));
  unit->set_prev_unit(prev_hash);
  unit->set_balance(balance);
  unit->set_sign(core::Signature());
  unit->set_dest(pub_key_to);
  unit->CalcHashAndFill();
  return AddUnit(unit, err);
}

std::shared_ptr<ambr::core::Unit> ambr::store::UnitStore::GetUnit(const ambr::core::UnitHash &hash){
  std::string string_readed;
  leveldb::Status status = db_unit_->Get(
                             leveldb::ReadOptions(),
                             leveldb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                             &string_readed);
  if(status.IsNotFound()){
    return std::shared_ptr<ambr::core::Unit>();
  }
  assert(status.ok());
  return ambr::core::Unit::CreateUnitByByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()));
}

ambr::store::UnitStore::UnitStore(){
  Init();
}


