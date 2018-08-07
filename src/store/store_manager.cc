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
      boost::posix_time::ptime pt = boost::posix_time::microsec_clock::universal_time();
      boost::posix_time::ptime pt_ori(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
      boost::posix_time::time_duration duration = pt-pt_ori;
      genesis_time_ = duration.total_milliseconds();
      std::shared_ptr<core::ValidatorUnit> unit_validate = std::make_shared<core::ValidatorUnit>();
      unit_validate->set_version(0x00000001);
      unit_validate->set_type(core::UnitType::Validator);
      unit_validate->set_public_key(unit->public_key());
      unit_validate->set_balance(init_validate);
      unit_validate->set_time_stamp(genesis_time_);
      unit_validate->set_percent(32);
      unit_validate->set_nonce(0);
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
      validator_store->set_current_nonce(0u);
      validator_store->set_current_validator(unit_validate->public_key());
      validator_store->set_validator_list(validator_list);

      //write genesis to database
      rocksdb::WriteBatch batch;
      std::shared_ptr<ReceiveUnitStore> rec_store = std::make_shared<ReceiveUnitStore>(unit);
      rec_store->set_version((uint32_t)0x00000001);
      rec_store->set_is_validate(true);
      std::vector<uint8_t> bytes = rec_store->SerializeByte();
      std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = unit->hash().bytes();
      batch.Put(handle_receive_unit_,
                rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
                rocksdb::Slice((const char*)bytes.data(), bytes.size()));
      std::shared_ptr<EnterValidatorSetUnitStore> enter_store = std::make_shared<EnterValidatorSetUnitStore>(enter_unit);
      enter_store->set_version((uint32_t)0x00000001);
      enter_store->set_is_validate(true);
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
  {//check prv unit
    core::UnitHash last_hash;
    if(!GetLastUnitHashByPubKey(send_unit->public_key(), last_hash)){
      if(err){
        *err = "Public key is not exist";
      }
      return false;
    }
    if(last_hash != send_unit->prev_unit()){
      if(err){
        *err = "Prv unit is not last unit of account";
      }
      return false;
    }
  }
  {//check account address
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
  rocksdb::Status status = batch.Put(handle_send_unit_, rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
            rocksdb::Slice((const char*)bytes.data(), bytes.size()));
  assert(status.ok());
  status = batch.Put(handle_account_, rocksdb::Slice((const char*)send_unit->public_key().bytes().data(), send_unit->public_key().bytes().size()),
            rocksdb::Slice((const char*)send_unit->hash().bytes().data(), send_unit->hash().bytes().size()));
  assert(status.ok());
  status = batch.Put(handle_new_account_, rocksdb::Slice((const char*)send_unit->public_key().bytes().data(), send_unit->public_key().bytes().size()),
            rocksdb::Slice((const char*)send_unit->hash().bytes().data(), send_unit->hash().bytes().size()));
  assert(status.ok());
  AddWaitForReceiveUnit(send_unit->dest(), send_unit->hash(), &batch);
  if(use_log){//TODO:use log module
    std::cout<<"Add unit for send!"<<std::endl;
    std::cout<<send_unit->hash().encode_to_hex()<<std::endl;
    std::cout<<store->SerializeJson()<<std::endl;
    std::cout<<"address:"<<ambr::core::GetAddressStringByPublicKey(send_unit->public_key())
            <<"'s last unit change to "<<send_unit->hash().encode_to_hex();
  }
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
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
  {//check prv unit
    core::UnitHash last_hash;
    if(!GetLastUnitHashByPubKey(receive_unit->public_key(), last_hash)){
      if(!receive_unit->prev_unit().is_zero()){
        if(err){
          *err = "Prv unit is not last unit of account";
        }
        return false;
      }
    }
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
  if(!prev_send_store){
    if(err){
      *err = "Send unit's previous unit is not found";
    }
    return false;
  }
  if(balance_old.data() !=
      prev_send_store->GetUnit()->balance().data()-send_unit_store->GetUnit()->balance().data()){
    if(err)*err = "Error balance number.";
    return false;
  }
  rocksdb::WriteBatch batch;
  auto receive_unit_store = std::make_shared<ReceiveUnitStore>(receive_unit);
  std::vector<uint8_t> bytes = receive_unit_store->SerializeByte();
  std::array<uint8_t,sizeof(ambr::core::UnitHash::ArrayType)> hash_bytes = receive_unit->hash().bytes();
  rocksdb::Status status = batch.Put(handle_receive_unit_, rocksdb::Slice((const char*)hash_bytes.data(), hash_bytes.size()),
            rocksdb::Slice((const char*)bytes.data(), bytes.size()));
  assert(status.ok());
  status = batch.Put(handle_account_, rocksdb::Slice((const char*)receive_unit->public_key().bytes().data(), receive_unit->public_key().bytes().size()),
            rocksdb::Slice((const char*)receive_unit->hash().bytes().data(), receive_unit->hash().bytes().size()));
  assert(status.ok());
  status = batch.Put(handle_new_account_, rocksdb::Slice((const char*)receive_unit->public_key().bytes().data(), receive_unit->public_key().bytes().size()),
            rocksdb::Slice((const char*)receive_unit->hash().bytes().data(), receive_unit->hash().bytes().size()));
  assert(status.ok());
  send_unit_store->set_receive_unit_hash(receive_unit->hash());
  bytes = send_unit_store->SerializeByte();
  status = batch.Put(handle_send_unit_, rocksdb::Slice((const char*)send_unit_store->unit()->hash().bytes().begin(), send_unit_store->unit()->hash().bytes().size()),
            rocksdb::Slice((const char*)bytes.data(), bytes.size()));
  assert(status.ok());
  RemoveWaitForReceiveUnit(receive_unit->public_key(), receive_unit->from(), &batch);
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

  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set_list =
      ambr::store::GetStoreManager()->GetValidatorSet();
  if(!validator_set_list){
    if(err){
      *err = "validator's ptr is null";
    }
    return false;
  }

  if(validator_set_list->IsValidator(unit->public_key())){
    if(err){
      *err = "Sender is not validator_set";
    }
    return false;
  }
  std::shared_ptr<store::UnitStore> tmp_unit = GetUnit(unit->prev_unit());
  while(tmp_unit){
    if(tmp_unit->GetUnit()->prev_unit().is_zero()){
      break;
    }
    if(tmp_unit->type() == UnitStore::ST_EnterValidatorSet){
      if(err){
        *err = "Enter validator_unit already published";
      }
      return false;
    }
    bool validated = false;
    switch(tmp_unit->type()){
      case UnitStore::ST_SendUnit:
        {
          std::shared_ptr<store::SendUnitStore> send_unit =
              std::dynamic_pointer_cast<store::SendUnitStore>(tmp_unit);
          if(send_unit->is_validate()){
            validated = true;
          }
        }
        break;
      case UnitStore::ST_ReceiveUnit:
        {
          std::shared_ptr<store::ReceiveUnitStore> receive_unit =
              std::dynamic_pointer_cast<store::ReceiveUnitStore>(tmp_unit);
          if(receive_unit->is_validate()){
            validated = true;
          }
        }
        break;
      case UnitStore::ST_EnterValidatorSet:
        {
          std::shared_ptr<store::EnterValidatorSetUnitStore> enter_unit =
              std::dynamic_pointer_cast<store::EnterValidatorSetUnitStore>(tmp_unit);
          if(enter_unit->is_validate()){
            validated = true;
          }
        }
        break;
      case UnitStore::ST_LeaveValidatorSet:
        {
          std::shared_ptr<store::LeaveValidatorSetUnitStore> leave_unit =
              std::dynamic_pointer_cast<store::LeaveValidatorSetUnitStore>(tmp_unit);
          if(leave_unit->is_validate()){
            validated = true;
          }
        }
        break;
    }
    if(!validated){
      break;
    }
    tmp_unit = GetUnit(tmp_unit->GetUnit()->prev_unit());
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
  status = batch.Put(
     handle_new_account_,
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
  status = batch.Put(
     handle_new_account_,
     rocksdb::Slice((const char*)unit->public_key().bytes().data(), unit->public_key().bytes().size()),
     rocksdb::Slice((const char*)unit->hash().bytes().data(), unit->hash().bytes().size()));
  assert(status.ok());
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
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
  std::shared_ptr<ambr::core::ValidatorUnit> prv_validate_unit = GetValidateUnit(unit->prev_unit());
  if(!prv_validate_unit){
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
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set_list = ambr::store::GetStoreManager()->GetValidatorSet();
  if(!validator_set_list){
    if(err){
      *err = "validator_set's ptr is null";
    }
    return false;
  }

  //check nonce
  core::PublicKey check_pub_key;
  if(!validator_set_list->GetNonceTurnValidator(unit->nonce(), check_pub_key) ||
     check_pub_key != unit->public_key() ||
     prv_validate_unit->nonce() == unit->nonce()){
    if(err){
      *err = "err nonce or validator";
    }
    return false;
  }
  //UPDATE validator_set
  validator_set_list->Update(unit->nonce());


  for(core::UnitHash hash:unit->check_list()){
    std::shared_ptr<ambr::store::UnitStore> tmp_unit = GetUnit(hash);
    if(!tmp_unit){
      if(err){
        *err = std::string("Checked hash is not exist:")+hash.encode_to_hex();
      }
      return false;
    }
    // check unit is not validated by validator
    switch(tmp_unit->type()){
      case ambr::store::UnitStore::ST_SendUnit:{
          std::shared_ptr<ambr::store::SendUnitStore> dy_unit =
              std::dynamic_pointer_cast<ambr::store::SendUnitStore>(tmp_unit);
          if(dy_unit->is_validate() == true){
            if(err){
              *err = "One Of check unit is invalidated by validator";
            }
            return false;
          }
          break;
        }
      case ambr::store::UnitStore::ST_ReceiveUnit:{
          std::shared_ptr<ambr::store::ReceiveUnitStore> dy_unit =
              std::dynamic_pointer_cast<ambr::store::ReceiveUnitStore>(tmp_unit);
          if(dy_unit->is_validate() == true){
            if(err){
              *err = "One Of check unit is invalidated by validator";
            }
            return false;
          }
          break;
        }
      case ambr::store::UnitStore::ST_EnterValidatorSet:{
          std::shared_ptr<ambr::store::EnterValidatorSetUnitStore> dy_unit =
              std::dynamic_pointer_cast<ambr::store::EnterValidatorSetUnitStore>(tmp_unit);
          if(dy_unit->is_validate() == true){
            if(err){
              *err = "One Of check unit is invalidated by validator";
            }
            return false;
          }
          break;
        }
      case ambr::store::UnitStore::ST_LeaveValidatorSet:{
          std::shared_ptr<ambr::store::LeaveValidatorSetUnitStore> dy_unit =
              std::dynamic_pointer_cast<ambr::store::LeaveValidatorSetUnitStore>(tmp_unit);
          if(dy_unit->is_validate() == true){
            if(err){
              *err = "One Of check unit is invalidated by validator";
            }
            return false;
          }
          break;
        }
      default:
        assert(0);
    }
  }
  //collect votes
  ambr::core::Amount all_balance,vote_balance;
  for(ambr::store::ValidatorItem validator_item: validator_set_list->validator_list()){
    if(unit->nonce() >= validator_item.enter_nonce_ &&
    (unit->nonce() < validator_item.leave_nonce_ || validator_item.leave_nonce_ == 0)){
      all_balance = all_balance+validator_item.balance_;

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
    if(!validator_set_list->IsValidator(vote_unit.public_key(), unit->nonce())){
      if(err){
        *err = "One of validate's sender is not in validator_set";
      }
      return false;
    }
    ValidatorItem validator_item;
    if(!validator_set_list->GetValidator(vote_unit.public_key(), validator_item)){
      if(err){
        *err = "On of validate's sender was not found in validator_set";
      }
      return false;
    }
    vote_balance += validator_item.balance_;
  }
  ambr::core::Amount max_percent;
  max_percent.set_data(PERCENT_MAX);
  if(max_percent < (vote_balance / all_balance)){
    assert(0);
  }
  if(unit->percent() != (vote_balance*max_percent / all_balance).data()){
    if(err){
      *err = "Error percent";
    }
    return false;
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

  //clear old vote and vote now
  ClearVote();
  //validator now
  if(unit->percent() > PERCENT_MAX/2){//passed
    validator_set_list->set_current_nonce(unit->nonce());
    validator_set_list->set_current_validator(unit->public_key());
    std::vector<ambr::core::UnitHash> checked_list = prv_validate_unit->check_list();
    for(const ambr::core::UnitHash& hash: checked_list){
      std::shared_ptr<ambr::store::UnitStore> unit_tmp = GetUnit(hash);
      while(unit_tmp){
        bool over = false;
        switch(unit_tmp->type()){
          case ambr::store::UnitStore::ST_SendUnit:{
              std::shared_ptr<ambr::store::SendUnitStore> send_unit =
                  std::dynamic_pointer_cast<ambr::store::SendUnitStore>(unit_tmp);
              if(!send_unit || send_unit->is_validate()){
                over = true;
                break;
              }
              send_unit->set_is_validate(true);
              std::vector<uint8_t> buf = send_unit->SerializeByte();
              status = batch.Put(
                    handle_send_unit_,
                    rocksdb::Slice((const char*)send_unit->unit()->hash().bytes().data(), send_unit->unit()->hash().bytes().size()),
                    rocksdb::Slice((const char*)buf.data(), buf.size()));
              assert(status.ok());
              unit_tmp = GetUnit(send_unit->GetUnit()->prev_unit());
              break;
            }
          case ambr::store::UnitStore::ST_ReceiveUnit:{
              std::shared_ptr<ambr::store::ReceiveUnitStore> receive_unit =
                  std::dynamic_pointer_cast<ambr::store::ReceiveUnitStore>(unit_tmp);
              if(!receive_unit || receive_unit->is_validate()){
                over = true;
                break;
              }
              receive_unit->set_is_validate(true);
              std::vector<uint8_t> buf = receive_unit->SerializeByte();
              status = batch.Put(
                    handle_receive_unit_,
                    rocksdb::Slice((const char*)receive_unit->unit()->hash().bytes().data(), receive_unit->unit()->hash().bytes().size()),
                    rocksdb::Slice((const char*)buf.data(), buf.size()));
              assert(status.ok());
              unit_tmp = GetUnit(receive_unit->GetUnit()->prev_unit());
              break;
            }
          case ambr::store::UnitStore::ST_EnterValidatorSet:{
              std::shared_ptr<ambr::store::EnterValidatorSetUnitStore> enter_unit =
                  std::dynamic_pointer_cast<ambr::store::EnterValidatorSetUnitStore>(unit_tmp);
              if(!enter_unit || enter_unit->is_validate()){
                over = true;
                break;
              }
              enter_unit->set_is_validate(true);
              std::vector<uint8_t> buf = enter_unit->SerializeByte();
              status = batch.Put(
                    handle_enter_validator_unit_,
                    rocksdb::Slice((const char*)enter_unit->unit()->hash().bytes().data(), enter_unit->unit()->hash().bytes().size()),
                    rocksdb::Slice((const char*)buf.data(), buf.size()));

              assert(status.ok());

              core::Amount new_balance = enter_unit->unit()->balance();
              unit_tmp = GetUnit(enter_unit->GetUnit()->prev_unit());
              core::Amount old_balance = unit_tmp->GetUnit()->balance();
              store::ValidatorItem validator_item;
              validator_item.validator_public_key_ = enter_unit->GetUnit()->public_key();
              validator_item.balance_ = old_balance-new_balance;
              validator_item.enter_nonce_ = unit->nonce()+2;
              validator_item.leave_nonce_ = 0;
              validator_set_list->JoinValidator(validator_item);

              break;
            }
          case ambr::store::UnitStore::ST_LeaveValidatorSet:{
              std::shared_ptr<ambr::store::LeaveValidatorSetUnitStore> leave_unit =
                  std::dynamic_pointer_cast<ambr::store::LeaveValidatorSetUnitStore>(unit_tmp);
              if(!leave_unit || leave_unit->is_validate()){
                over = true;
                break;
              }
              leave_unit->set_is_validate(true);
              std::vector<uint8_t> buf = leave_unit->SerializeByte();
              status = batch.Put(
                    handle_enter_validator_unit_,
                    rocksdb::Slice((const char*)leave_unit->unit()->hash().bytes().data(), leave_unit->unit()->hash().bytes().size()),
                    rocksdb::Slice((const char*)buf.data(), buf.size()));
              unit_tmp = GetUnit(leave_unit->GetUnit()->prev_unit());
              validator_set_list->LeaveValidator(leave_unit->unit()->public_key(), unit->nonce());
              break;
            }
          default:
            assert(0);
        }
        if(over)break;
      }
    }
  }
  std::vector<uint8_t> validator_set_buf = validator_set_list->SerializeByte();
  status = batch.Put(handle_validator_set_,
                     rocksdb::Slice(validate_set_key),
                     rocksdb::Slice((const char*)validator_set_buf.data(), validator_set_buf.size()));
  assert(status.ok());
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
  assert(status.ok());
  return true;
}

bool ambr::store::StoreManager::AddVote(std::shared_ptr<ambr::core::VoteUnit> unit, std::string *err){
  if(!unit){
    if(err){
      *err = "Vote Unit is null";
    }
    return false;
  }
  if(!unit->Validate(err)){
    return false;
  }
  core::UnitHash last_validate_unit_hash;
  if(!GetLastValidateUnit(last_validate_unit_hash) || unit->validator_unit_hash() != last_validate_unit_hash){
    if(err){
      *err = "Hash is not right which is vote for.";
    }
    return false;
  }
  std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = GetValidateUnit(last_validate_unit_hash);
  if(!validator_unit){
    if(err){
      *err = "last validator unit is not found";
    }
    return false;
  }
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set = GetValidatorSet();
  ValidatorItem item;
  if(!validator_set->IsValidator(unit->public_key(), validator_unit->nonce())){
    if(err){
      *err = "Voter is not in validator_set";
    }
    return false;
  }
  for(std::shared_ptr<core::VoteUnit> vote_unit:vote_list_){
    if(vote_unit->public_key() == unit->public_key()){
      if(err){
        *err = "Voter was voted";
      }
      return false;
    }
  }
  vote_list_.push_back(unit);
  return true;
}

void ambr::store::StoreManager::ClearVote(){
  vote_list_.clear();
}

void ambr::store::StoreManager::UpdateNewUnitMap(const std::vector<core::UnitHash> &validator_check_list){
  std::list<ambr::core::PublicKey> will_remove;
  rocksdb::Iterator* it = db_unit_->NewIterator(rocksdb::ReadOptions(), handle_new_account_);
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    ambr::core::PublicKey pub_key;
    ambr::core::UnitHash unit_hash;
    pub_key.set_bytes(it->key().data(), it->key().size());
    unit_hash.set_bytes(it->value().data(), it->value().size());
    if(std::find(validator_check_list.begin(), validator_check_list.end(), unit_hash) != validator_check_list.end()){
      will_remove.push_back(pub_key);
    }
  }
  rocksdb::WriteBatch batch;
  rocksdb::Status status;
  for(const core::PublicKey& pub_key:will_remove){
    status = batch.Delete(
         handle_new_account_,
         rocksdb::Slice((const char*)pub_key.bytes().data(), pub_key.bytes().size()));
    assert(status.ok());
  }
  status = db_unit_->Write(rocksdb::WriteOptions(), &batch);
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

std::unordered_map<ambr::core::PublicKey, ambr::core::UnitHash> ambr::store::StoreManager::GetNewUnitMap(){
  std::unordered_map<ambr::core::PublicKey, ambr::core::UnitHash> rtn;
  rocksdb::Iterator* it = db_unit_->NewIterator(rocksdb::ReadOptions(), handle_new_account_);
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    ambr::core::PublicKey pub_key;
    ambr::core::UnitHash unit_hash;
    pub_key.set_bytes(it->key().data(), it->key().size());
    unit_hash.set_bytes(it->value().data(), it->value().size());
    rtn[pub_key] = unit_hash;
  }
  return rtn;
}

std::shared_ptr<ambr::store::ValidatorSetStore> ambr::store::StoreManager::GetValidatorSet(){
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
                                                 std::shared_ptr<ambr::core::Unit>& unit_join,
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
                                                  std::shared_ptr<ambr::core::Unit>& unit_leave,
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

bool ambr::store::StoreManager::PublishValidator(
    const core::PrivateKey& pri_key,
    core::UnitHash* tx_hash,
    std::shared_ptr<ambr::core::ValidatorUnit>& unit_validator,
    std::string* err
    ){
  std::shared_ptr<core::ValidatorUnit> unit = std::make_shared<core::ValidatorUnit>();
  unit->set_version((uint32_t)0x000000001);
  unit->set_type(core::UnitType::Validator);
  unit->set_public_key(core::GetPublicKeyByPrivateKey(pri_key));
  core::UnitHash last_validator_hash;
  if(!GetLastValidateUnit(last_validator_hash)){
    if(err){
      *err = "Get last validator unit faild";
    }
    return false;
  }
  unit->set_prev_unit(last_validator_hash);
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set = GetValidatorSet();
  if(!validator_set){
    if(err){
      *err = "Get validator set faild";
    }
    return false;
  }
  ValidatorItem validator_item;
  if(!validator_set->GetValidator(core::GetPublicKeyByPrivateKey(pri_key), validator_item)){
    if(err){
      *err = "Get validator balance faild";
    }
    return false;
  }

  //add vote
  std::list<std::shared_ptr<ambr::core::VoteUnit>> vote_list = GetVoteList();
  for(std::shared_ptr<ambr::core::VoteUnit> vote_item:vote_list){
    unit->add_vote_hash_list(vote_item->hash());
    unit->add_vote_list(*vote_item);
  }

  //add check unit
  auto new_unit_map = GetNewUnitMap();
  for(auto item: new_unit_map){
    unit->add_check_list(item.second);
  }
  unit->set_balance(validator_item.balance_);
  unit->set_nonce(GetNonceByNowTime());
  //calc percent
  ambr::core::Amount all_balance,vote_balance;
  for(ambr::store::ValidatorItem validator_item: validator_set->validator_list()){
    if(unit->nonce() >= validator_item.enter_nonce_ &&
    (unit->nonce() < validator_item.leave_nonce_ || validator_item.leave_nonce_ == 0)){
      all_balance = all_balance+validator_item.balance_;
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
    ValidatorItem item;
    if(!validator_set->GetValidator(vote_unit.public_key(), item) ||
       !validator_set->IsValidator(vote_unit.public_key(), unit->nonce())){
      if(err){
        *err = "One of validate's sender is not in validator_set";
      }
      return false;
    }
    vote_balance += item.balance_;
    std::cout<<"!!!!!"<<vote_balance.encode_to_dec()<<"|"<<item.validator_public_key_.encode_to_hex()<<std::endl;
  }


  unit->set_percent((uint32_t)(vote_balance*ambr::core::Amount(PERCENT_MAX) / all_balance).data());
  //check percent
  std::shared_ptr<ambr::core::ValidatorUnit> last_validator_unit = GetLastestValidateUnit();
  if(unit->percent() > PERCENT_MAX/2){//passed
    if(!last_validator_unit){
      if(err){
        *err = "latest validator unit is not found";
      }
      return false;
    }
    UpdateNewUnitMap(last_validator_unit->check_list());
  }
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);

  if(!AddValidateUnit(unit, err)){
    return false;
  }
  *tx_hash = unit->hash();
  unit_validator = unit;
  // add ValidatorUnit success, publish vote
  std::shared_ptr<ambr::core::VoteUnit> tmp_unit;
  if(!PublishVote(pri_key, true, tmp_unit, err)){
    return false;
  }
  return true;
}

bool ambr::store::StoreManager::PublishVote(const core::PrivateKey& pri_key,
                                            bool accept,
                                            std::shared_ptr<ambr::core::VoteUnit>& unit_vote,
                                            std::string* err){
  std::shared_ptr<core::VoteUnit> unit = std::make_shared<core::VoteUnit>();
  unit->set_version(0x00000001);
  unit->set_type(core::UnitType::Vote);
  unit->set_public_key(core::GetPublicKeyByPrivateKey(pri_key));
  //unit->set_prev_unit;
  std::shared_ptr<ambr::store::ValidatorSetStore> validator_set = GetValidatorSet();
  if(!validator_set){
    if(err){
      *err = "Can't find validator set";
    }
    return false;
  }
  ValidatorItem validator_item;
  if(!validator_set->GetValidator(core::GetPublicKeyByPrivateKey(pri_key), validator_item)){
    if(err){
      *err = "This account is not in validator-set";
    }
    return false;
  }
  unit->set_balance(validator_item.balance_);
  unit->set_accept(accept);
  core::UnitHash last_validator_hash;
  if(!GetLastValidateUnit(last_validator_hash)){
    if(err){
      *err = "Con't find last validator-unit hash";
    }
    return false;
  }
  unit->set_validator_unit_hash(last_validator_hash);
  unit->CalcHashAndFill();
  unit->SignatureAndFill(pri_key);
  if(!AddVote(unit, err)){
    return false;
  }
  unit_vote = unit;
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
  rocksdb::Status status = db_unit_->Get(rocksdb::ReadOptions(), handle_send_unit_, rocksdb::Slice((const char*)hash.bytes().data(), hash.bytes().size()), &string_readed);
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

std::shared_ptr<ambr::core::ValidatorUnit> ambr::store::StoreManager::GetLastestValidateUnit(){
  core::UnitHash last_validate_unit_hash;
  if(!GetLastValidateUnit(last_validate_unit_hash)){
    return nullptr;
  }
  std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = GetValidateUnit(last_validate_unit_hash);
  if(!validator_unit){
    return nullptr;
  }
  return validator_unit;
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

std::list<std::shared_ptr<ambr::core::VoteUnit>> ambr::store::StoreManager::GetVoteList(){
  return vote_list_;
}

uint64_t ambr::store::StoreManager::GetNonceByNowTime(){
  boost::posix_time::ptime pt = boost::posix_time::microsec_clock::universal_time();
  boost::posix_time::ptime pt_ori(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
  boost::posix_time::time_duration duration = pt-pt_ori;
  uint64_t interval = duration.total_milliseconds() - ambr::store::GetStoreManager()->GetGenesisTime();
  return (interval/GetValidateUnitInterval());
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


