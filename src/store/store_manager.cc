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
static const ambr::core::Amount init_balance=(boost::multiprecision::uint128_t)530000000000*1000;
static const ambr::core::Amount init_validate=(boost::multiprecision::uint128_t)100000000000*1000;
static const std::string last_validate_key = "lv";
static const std::string validate_set_key = "validate_set_key";
static const ambr::core::Amount min_validator_balance = (boost::multiprecision::uint128_t)100000000*1000;
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
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("new_accout", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("handle_wait_for_receive", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("validator_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("enter_validator_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("leave_validator_unit", rocksdb::ColumnFamilyOptions()));
  column_families.push_back(rocksdb::ColumnFamilyDescriptor("validator_set", rocksdb::ColumnFamilyOptions()));
  rocksdb::Status status = rocksdb::DB::Open(options, path, column_families, &column_families_handle, &db_unit_);
  assert(status.ok());
  handle_send_unit_ = column_families_handle[0];
  handle_receive_unit_ = column_families_handle[1];
  handle_account_ = column_families_handle[2];
  handle_new_account_ = column_families_handle[3];
  handle_wait_for_receive_ = column_families_handle[4];
  handle_validator_unit_ = column_families_handle[5];
  handle_enter_validator_unit_ = column_families_handle[6];
  handle_leave_validator_unit_ = column_families_handle[7];
  handle_validator_set_ = column_families_handle[8];

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
      unit->set_from(core::Address());
      unit->CalcHashAndFill();
      unit->SignatureAndFill(core::PrivateKey("25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC"));

      //construct enter validator set unit of genesis
      std::shared_ptr<core::EnterValidateSetUint> enter_unit = std::make_shared<core::EnterValidateSetUint>();
      enter_unit->set_version(0x00000001);
      enter_unit->set_type(core::UnitType::EnterValidateSet);
      enter_unit->set_public_key(unit->public_key());
      enter_unit->set_prev_unit(unit->hash());
      enter_unit->set_balance(init_balance-init_validate);
      enter_unit->CalcHashAndFill();
      enter_unit->SignatureAndFill(core::PrivateKey("25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC"));

      //construct validate unit of genesis
      std::shared_ptr<core::ValidatorUnit> unit_validate = std::make_shared<core::ValidatorUnit>();
      unit_validate->set_version(0x00000001);
      unit_validate->set_type(core::UnitType::Validator);
      unit_validate->set_public_key(unit->public_key());
      unit_validate->set_balance(init_validate);
      unit_validate->add_check_list(enter_unit->hash());
      unit_validate->CalcHashAndFill();
      unit_validate->SignatureAndFill(core::PrivateKey("25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC"));
      unit_validate->Validate(nullptr);
      //construct validator set of genesis
      std::shared_ptr<store::ValidatorSetStore> validator_store = std::make_shared<store::ValidatorSetStore>();
      validator_store->set_version(0x00000001);
      std::list<store::ValidatorItem> validator_list;
      store::ValidatorItem item;
      item.validator_public_key_ = unit_validate->public_key();
      item.balance_ = unit_validate->balance();
      item.enter_nonce_ = 0;
      item.leave_nonce_ = 0;
      validator_list.push_back(item);
      validator_store->set_validator_list(validator_list);
      //write genesis to database
      rocksdb::WriteBatch batch;
      std::shared_ptr<ReceiveUnitStore> rec_store = std::make_shared<ReceiveUnitStore>(unit);
      std::vector<uint8_t> bytes = rec_store->SerializeByte();
      std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = unit->hash().bytes();
      batch.Put(handle_receive_unit_,
                rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
                rocksdb::Slice((const char*)bytes.data(), bytes.size()));
      std::shared_ptr<EnterValidatorSetUnitStore> enter_store = std::make_shared<EnterValidatorSetUnitStore>(enter_unit);
      std::vector<uint8_t> enter_buf = enter_store->SerializeByte();
      batch.Put(handle_enter_validator_unit_,
                rocksdb::Slice((const char*)enter_unit->hash().bytes().data(), enter_unit->hash().bytes().size()),
                rocksdb::Slice((const char*)enter_buf.data(), enter_buf.size()));
      batch.Put(handle_account_,
                rocksdb::Slice((const char*)unit->public_key().bytes().data(), unit->public_key().bytes().size()),
                rocksdb::Slice((const char*)enter_unit->hash().bytes().data(), enter_unit->hash().bytes().size()));
      std::vector<uint8_t> validate_buf = unit_validate->SerializeByte();
      batch.Put(handle_validator_unit_,
                rocksdb::Slice((const char*)unit_validate->hash().bytes().data(), unit_validate->hash().bytes().size()),
                rocksdb::Slice((const char*)validate_buf.data(), validate_buf.size())
                );
      batch.Put(handle_validator_unit_,
                rocksdb::Slice(last_validate_key),
                rocksdb::Slice((const char*)unit_validate->hash().bytes().data(), unit_validate->hash().bytes().size())
                );
      std::vector<uint8_t> validator_set_buf = validator_store->SerializeByte();
      batch.Put(handle_validator_set_,
                rocksdb::Slice(validate_set_key),
                rocksdb::Slice((const char*)validator_set_buf.data(), validator_set_buf.size())
                );
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
  batch.Put(handle_new_account_, rocksdb::Slice((const char*)send_unit->public_key().bytes().data(), send_unit->public_key().bytes().size()),
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

  if(!send_unit_store->receive_unit_hash().is_zero()){//received
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

bool ambr::store::StoreManager::AddValidateUnit(std::shared_ptr<ambr::core::ValidatorUnit> unit, std::string *err){
  if(!unit){
    if(err){
      *err = "Unit point is null";
    }
    return false;
  }
  std::string validate_err;
  if(!unit->Validate(&validate_err)){
    if(err){
      *err = std::string("Validator unit is not right:")+validate_err;
    }
    return false;
  }
  if(!GetValidateUnit(unit->prev_unit())){
    if(err){
      *err = "Previous validator unit is not exist";
    }
    return false;
  }
  if(GetValidateUnit(unit->hash())){
    if(err){
      *err = "Validator unit already exist";
    }
    return false;
  }
  for(core::UnitHash hash:unit->check_list()){
    if(!GetUnit(hash)){
      if(err){
        *err = std::string("Checked hash is not exist:")+hash.encode_to_hex();
      }
      return false;
    }
  }
  for(core::VoteUnit vote_unit:unit->vote_list()){
    std::string validate_err;
    if(!vote_unit.Validate(&validate_err)){
      if(err){
        *err = std::string("One of validate unit is not right:")+validate_err;
      }
      return false;
    }
  }

  //write to db
  std::vector<uint8_t> buf = unit->SerializeByte();
  rocksdb::WriteBatch batch;
  rocksdb::Status status = batch.Put(
     handle_validator_unit_,
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()),
     rocksdb::Slice((const char*)buf.data(), buf.size()));
  assert(status.ok());
  status = batch.Put(
     handle_validator_unit_,
     rocksdb::Slice(last_validate_key),
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()));
  assert(status.ok());
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
  assert(status.ok());
  return true;
}

bool ambr::store::StoreManager::AddEnterValidatorSetUnit(std::shared_ptr<ambr::core::EnterValidateSetUint> unit, std::string *err){
  if(!unit){
    if(err){
      *err = "Unit pointer is null";
    }
    return false;
  }
  if(!unit->Validate(err)){
    return false;
  }
  core::UnitHash last_hash;
  if(!GetLastUnitHashByPubKey(unit->public_key(), last_hash)){
    if(err){
      *err = "Public key is not exist";
    }
    return false;
  }
  if(last_hash != unit->prev_unit()){
    if(err){
      *err = "Prv unit is not last unit of account";
    }
    return false;
  }
  std::shared_ptr<ambr::store::UnitStore> prv_store = GetUnit(last_hash);
  if(!prv_store){
    if(err){
      *err = "Previous unit is not exist";
    }
    return false;
  }

  if(unit->balance().data() - prv_store->GetUnit()->balance().data() < min_validator_balance.data()){
    if(err){
      *err = "Cash deposit is not enough";
    }
    return false;
  }

  //write to db
  std::shared_ptr<EnterValidatorSetUnitStore> store = std::make_shared<EnterValidatorSetUnitStore>(unit);
  std::vector<uint8_t> buf = store->SerializeByte();
  rocksdb::WriteBatch batch;
  rocksdb::Status status = batch.Put(
     handle_enter_validator_unit_,
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()),
     rocksdb::Slice((const char*)buf.data(), buf.size()));
  assert(status.ok());
  status = batch.Put(
     handle_account_,
     rocksdb::Slice((const char*)unit->public_key().bytes().data(), unit->public_key().bytes().size()),
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()));
  assert(status.ok());
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
  assert(status.ok());
  return true;
}

bool ambr::store::StoreManager::AddLeaveValidatorSetUnit(std::shared_ptr<ambr::core::LeaveValidateSetUint> unit, std::string *err){
  if(!unit){
    if(err){
      *err = "Unit pointer is null";
    }
    return false;
  }
  if(!unit->Validate(err)){
    return false;
  }
  core::UnitHash last_hash;
  if(!GetLastUnitHashByPubKey(unit->public_key(), last_hash)){
    if(err){
      *err = "Public key is not exist";
    }
    return false;
  }
  if(last_hash != unit->prev_unit()){
    if(err){
      *err = "Prv unit is not last unit of account";
    }
    return false;
  }
  std::shared_ptr<ambr::store::UnitStore> prv_store = GetUnit(last_hash);
  if(!prv_store){
    if(err){
      *err = "Previous unit is not exist";
    }
    return false;
  }

  //TODO banlance validate
  //write to db
  std::shared_ptr<LeaveValidatorSetUnitStore> store = std::make_shared<LeaveValidatorSetUnitStore>(unit);
  std::vector<uint8_t> buf = store->SerializeByte();
  rocksdb::WriteBatch batch;
  rocksdb::Status status = batch.Put(
     handle_leave_validator_unit_,
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()),
     rocksdb::Slice((const char*)buf.data(), buf.size()));
  assert(status.ok());
  status = batch.Put(
     handle_account_,
     rocksdb::Slice((const char*)unit->public_key().bytes().data(), unit->public_key().bytes().size()),
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()));
  assert(status.ok());
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
  assert(status.ok());
  return true;
}

bool ambr::store::StoreManager::GetLastValidateUnit(core::UnitHash& hash){
  std::string value_get;
  rocksdb::Status status = db_unit_->Get(
        rocksdb::ReadOptions(),
        handle_validator_unit_,
        rocksdb::Slice(last_validate_key), &value_get);
  if(status.IsNotFound()){
    return false;
  }
  assert(status.ok());
  hash.set_bytes(value_get.data(), value_get.size());
  return true;
}

std::list<std::shared_ptr<ambr::core::ValidatorUnit> > ambr::store::StoreManager::GetValidateHistory(size_t count){
  std::list<std::shared_ptr<ambr::core::ValidatorUnit> > rtn;
  core::UnitHash unit_hash;
  if(!GetLastValidateUnit(unit_hash)){
    return rtn;
  }
  for(size_t i = 0; i < count; i++){
    std::shared_ptr<core::ValidatorUnit> unit = GetValidateUnit(unit_hash);
    if(!unit){
      return rtn;
    }
    rtn.push_back(unit);
    if(unit->prev_unit().is_zero()){
      return rtn;
    }
    unit_hash = unit->prev_unit();
  }
  return rtn;
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
    }else if(store->type() == UnitStore::ST_EnterValidatorSet){
      balance = store->GetUnit()->balance();
      return true;
    }else if(store->type() == UnitStore::ST_LeaveValidatorSet){
      balance = store->GetUnit()->balance();
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

std::shared_ptr<ambr::store::ValidatorSetStore> ambr::store::StoreManager::GetValidatorSet(){
  std::make_shared<ValidatorSetStore>();
  std::string value_get;
  rocksdb::Status status = db_unit_->Get(
        rocksdb::ReadOptions(), handle_validator_set_,
        rocksdb::Slice(validate_set_key), &value_get);
  if(status.IsNotFound()){
    assert(0);
  }
  assert(status.ok());
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set =
      std::make_shared<ValidatorSetStore>();
  assert(validator_set->DeSerializeByte(std::vector<uint8_t>(value_get.begin(), value_get.end())));
  return validator_set;
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

bool ambr::store::StoreManager::JoinValidatorSet(const core::PrivateKey& pri_key,
                                                 const core::Amount& count,
                                                 core::UnitHash* tx_hash,
                                                 std::shared_ptr<ambr::core::EnterValidateSetUint>& unit_join,
                                                 std::string* err){
  std::shared_ptr<ambr::core::EnterValidateSetUint> unit = std::make_shared<ambr::core::EnterValidateSetUint>();
  core::PublicKey pub_key = core::GetPublicKeyByPrivateKey(pri_key);
  core::UnitHash last_hash;
  std::shared_ptr<ambr::store::UnitStore> last_unit;
  if(!GetLastUnitHashByPubKey(pub_key, last_hash)){
    if(err){
      *err = "Can't find account";
    }
    return false;
  }
  if(!(last_unit = GetUnit(last_hash))){
    if(err){
      *err = "Can't find lastest unit";
    }
    return false;
  }

  unit->set_version(0x00000001);
  unit->set_type(ambr::core::UnitType::EnterValidateSet);
  unit->set_public_key(pub_key);
  unit->set_prev_unit(last_hash);
  if(last_unit->GetUnit()->balance() < count){
    if(err){
      *err = "Balance is not enough";
    }
    return false;
  }
  unit->set_balance(last_unit->GetUnit()->balance() - count);
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);
  if(!AddEnterValidatorSetUnit(unit, err)){
    return false;
  }
  if(tx_hash){
    *tx_hash = unit->hash();
  }
  unit_join = unit;
  return true;
}

bool ambr::store::StoreManager::LeaveValidatorSet(const core::PrivateKey& pri_key,
                                                  const core::Amount& count,
                                                  core::UnitHash* tx_hash,
                                                  std::shared_ptr<ambr::core::LeaveValidateSetUint>& unit_leave,
                                                  std::string* err)
{
  std::shared_ptr<ambr::core::LeaveValidateSetUint> unit = std::make_shared<ambr::core::LeaveValidateSetUint>();
  core::PublicKey pub_key = core::GetPublicKeyByPrivateKey(pri_key);
  core::UnitHash last_hash;
  std::shared_ptr<ambr::store::UnitStore> last_unit;
  if(!GetLastUnitHashByPubKey(pub_key, last_hash)){
    if(err){
      *err = "Can't find account";
    }
    return false;
  }
  if(!(last_unit = GetUnit(last_hash))){
    if(err){
      *err = "Can't find lastest unit";
    }
    return false;
  }

  unit->set_version(0x00000001);
  unit->set_type(ambr::core::UnitType::LeaveValidateSet);
  unit->set_public_key(pub_key);
  unit->set_prev_unit(last_hash);
  unit->set_unfreeze_count(count);
  //TODO unfreeze validate

  unit->set_balance(last_unit->GetUnit()->balance());
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);

  if(!AddLeaveValidatorSetUnit(unit, err)){
    return false;
  }
  if(tx_hash){
    *tx_hash = unit->hash();
  }
  unit_leave = unit;
  return true;
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
  std::shared_ptr<ambr::store::UnitStore> unit;
  if(unit = GetSendUnit(hash)){
    return unit;
  }else if(unit = GetReceiveUnit(hash)){
    return unit;
  }else if(unit = GetEnterValidatorSetUnit(hash)){
    return unit;
  }else if(unit = GetLeaveValidatorSetUnit(hash)){
    return unit;
  }else{
    return nullptr;
  }
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

std::shared_ptr<ambr::core::ValidatorUnit> ambr::store::StoreManager::GetValidateUnit(const ambr::core::UnitHash &hash){
  std::shared_ptr<ambr::core::ValidatorUnit> rtn;
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                                      rocksdb::ReadOptions(),
                                      handle_validator_unit_,
                                      rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                                      &string_readed);
  if(status.IsNotFound()){
    return rtn;
  }
  assert(status.ok());
  rtn = std::make_shared<ambr::core::ValidatorUnit>();
  if(rtn->DeSerializeByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()))){
    return rtn;
  }
  return std::shared_ptr<ambr::core::ValidatorUnit>();
}

std::shared_ptr<ambr::store::EnterValidatorSetUnitStore> ambr::store::StoreManager::GetEnterValidatorSetUnit(const ambr::core::UnitHash &hash){
  std::shared_ptr<EnterValidatorSetUnitStore> rtn;
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                                      rocksdb::ReadOptions(),
                                      handle_enter_validator_unit_,
                                      rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                                      &string_readed);
  if(status.IsNotFound()){
    return rtn;
  }
  assert(status.ok());
  rtn = std::make_shared<EnterValidatorSetUnitStore>();
  if(rtn->DeSerializeByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()))){
    return rtn;
  }
  return std::shared_ptr<EnterValidatorSetUnitStore>();
}

std::shared_ptr<ambr::store::LeaveValidatorSetUnitStore> ambr::store::StoreManager::GetLeaveValidatorSetUnit(const ambr::core::UnitHash &hash){
  std::shared_ptr<LeaveValidatorSetUnitStore> rtn;
  std::string string_readed;
  rocksdb::Status status = db_unit_->Get(
                                      rocksdb::ReadOptions(),
                                      handle_leave_validator_unit_,
                                      rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()),
                                      &string_readed);
  if(status.IsNotFound()){
    return rtn;
  }
  assert(status.ok());
  rtn = std::make_shared<LeaveValidatorSetUnitStore>();
  if(rtn->DeSerializeByte(std::vector<uint8_t>(string_readed.begin(), string_readed.end()))){
    return rtn;
  }
  return std::shared_ptr<ambr::store::LeaveValidatorSetUnitStore>();
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


