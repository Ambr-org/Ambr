#include "unit_store.h"
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <core/unit.h>

std::shared_ptr<ambr::store::UnitStore> ambr::store::UnitStore::CreateUnitStoreByBytes(const std::vector<uint8_t> &buf){
  std::shared_ptr<ambr::core::Unit> unit = core::Unit::CreateUnitByByte(buf);
  if(!unit)return std::shared_ptr<store::UnitStore>();
  if(unit->type() == core::UnitType::send){
    std::shared_ptr<core::SendUnit> send_unit = std::dynamic_pointer_cast<core::SendUnit>(unit);
    return std::make_shared<store::SendUnitStore>(send_unit);
  }else if(unit->type() == core::UnitType::receive){
    std::shared_ptr<core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<core::ReceiveUnit>(unit);
    return std::make_shared<store::ReceiveUnitStore>(receive_unit);
  }else{
    return std::shared_ptr<store::UnitStore>();
  }
}

ambr::store::SendUnitStore::SendUnitStore(std::shared_ptr<core::SendUnit> unit):
  UnitStore(ST_SendUnit),
  unit_(unit){
  //assert(unit);
}

std::shared_ptr<ambr::core::SendUnit> ambr::store::SendUnitStore::unit(){
  return unit_;
}

ambr::core::UnitHash ambr::store::SendUnitStore::receive_unit_hash() const{
  return receive_unit_hash_;
}

void ambr::store::SendUnitStore::set_receive_unit_hash(const ambr::core::UnitHash hash){
  receive_unit_hash_ = hash;
}

std::string ambr::store::SendUnitStore::SerializeJson() const{
  assert(unit_);
  boost::property_tree::ptree pt;
  boost::property_tree::ptree store_pt;
  std::stringstream stream(unit_->SerializeJson());
  try{
    boost::property_tree::read_json(stream, pt);
    store_pt.put("version", version_);
    store_pt.put("receive_unit_hash", receive_unit_hash_.encode_to_hex());
    store_pt.put("validated_hash", validated_hash_.encode_to_hex());
    pt.add_child("store_addtion", store_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::SendUnitStore::DeSerializeJson(const std::string &json){
  boost::property_tree ::ptree pt;
  std::stringstream stream(json);
  boost::property_tree::read_json(stream, pt);
  try{
    version_ = pt.get<uint32_t>("store_addtion.version");
    if(version_ == 0x00000001){
      receive_unit_hash_.decode_from_hex(pt.get<std::string>("store_addtion.receive_unit_hash"));
      validated_hash_.decode_from_hex(pt.get<std::string>("store_addtion.validated_hash"));
    }else{
      return false;
    }
    unit_ = std::make_shared<core::SendUnit>();
    if(!unit_->DeSerializeJson(json)){
      return false;
    }
  }catch(...){
    return false;
  }
  return true;
}

std::vector<uint8_t> ambr::store::SendUnitStore::SerializeByte() const{
  assert(unit_);
  std::vector<uint8_t> rtn = unit_->SerializeByte();
  uint32_t len=rtn.size();
  std::vector<uint8_t> len_buf;
  len_buf.resize(sizeof(len));
  memcpy(len_buf.data(),&len,sizeof(len));
  rtn.insert(rtn.begin(),len_buf.begin(),len_buf.end());
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  rtn.insert(rtn.end(),receive_unit_hash_.bytes().begin(), receive_unit_hash_.bytes().end());
  rtn.insert(rtn.end(),validated_hash_.bytes().begin(), validated_hash_.bytes().end());
  return rtn;
}

bool ambr::store::SendUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::SendUnit>();
  uint32_t len;
  memcpy(&len,buf.data(),sizeof(len));
  std::vector<uint8_t> unit_buf;
  unit_buf.resize(len);
  memcpy(unit_buf.data(),buf.data()+sizeof(len),len);
  if(!unit_->DeSerializeByte(unit_buf)){
    return false;
  }

  size_t used_count = len+sizeof(len);
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)+sizeof(receive_unit_hash_)+sizeof(validated_hash_)){
      return false;
    }
    memcpy(&receive_unit_hash_, src, sizeof(receive_unit_hash_));
    src += sizeof(receive_unit_hash_);
    memcpy(&validated_hash_, src, sizeof(validated_hash_));
    return true;
  }//else if(other version)
  return false;
}

std::shared_ptr<ambr::core::Unit> ambr::store::SendUnitStore::GetUnit(){
  return unit_;
}


ambr::store::ReceiveUnitStore::ReceiveUnitStore(std::shared_ptr<core::ReceiveUnit> unit):
  UnitStore(ST_ReceiveUnit),
  unit_(unit){
  //assert(unit);
}

std::shared_ptr<ambr::core::ReceiveUnit> ambr::store::ReceiveUnitStore::unit(){
  return unit_;
}

std::string ambr::store::ReceiveUnitStore::SerializeJson() const{
  assert(unit_);
  boost::property_tree::ptree pt;
  boost::property_tree::ptree store_pt;
  std::stringstream stream(unit_->SerializeJson());
  try{
    boost::property_tree::read_json(stream, pt);
    store_pt.put("version", version_);
    store_pt.put("validated_hash", validated_hash_.encode_to_hex());
    pt.add_child("store_addtion", store_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::ReceiveUnitStore::DeSerializeJson(const std::string &json){
  boost::property_tree::ptree pt;
  std::stringstream stream(json);
  boost::property_tree::read_json(stream, pt);
  try{
    version_ = pt.get<uint32_t>("store_addtion.version");
    if(version_ == 0x00000001){
      //deserialize other addtion
      validated_hash_.decode_from_hex(pt.get<std::string>("store_addtion.validated_hash"));
    }
    unit_ = std::make_shared<core::ReceiveUnit>();
    if(!unit_->DeSerializeJson(json)){
      return false;
    }
  }catch(...){
    return false;
  }
  return true;
}

std::vector<uint8_t> ambr::store::ReceiveUnitStore::SerializeByte() const{
  assert(unit_);
  std::vector<uint8_t> rtn = unit_->SerializeByte();
  uint32_t len=rtn.size();
  std::vector<uint8_t> len_buf;
  len_buf.resize(sizeof(len));
  memcpy(len_buf.data(),&len,sizeof(len));
  rtn.insert(rtn.begin(),len_buf.begin(),len_buf.end());
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  rtn.insert(rtn.end(), validated_hash_.bytes().begin(), validated_hash_.bytes().end());
  return rtn;
}

bool ambr::store::ReceiveUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::ReceiveUnit>();
  uint32_t len;
  memcpy(&len,buf.data(),sizeof(len));
  std::vector<uint8_t> unit_buf;
  unit_buf.resize(len);
  memcpy(unit_buf.data(),buf.data()+sizeof(len),len);
  if(!unit_->DeSerializeByte(unit_buf)){
    return false;
  }

  size_t used_count = len+sizeof(len);
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)+sizeof(validated_hash_)){
      return false;
    }
    memcpy(&validated_hash_, src, sizeof(validated_hash_));
    return true;
  }//else if(other version)
  return false;
}

std::shared_ptr<ambr::core::Unit> ambr::store::ReceiveUnitStore::GetUnit(){
  return unit_;
}

//=========================

ambr::store::ValidatorUnitStore::ValidatorUnitStore(std::shared_ptr<core::ValidatorUnit> unit):
  UnitStore(ST_Validator),
  unit_(unit){
  //assert(unit);
}

std::shared_ptr<ambr::core::ValidatorUnit> ambr::store::ValidatorUnitStore::unit(){
  return unit_;
}

std::string ambr::store::ValidatorUnitStore::SerializeJson() const{
  assert(unit_);
  boost::property_tree::ptree pt;
  boost::property_tree::ptree store_pt;
  std::stringstream stream(unit_->SerializeJson());
  try{
    boost::property_tree::read_json(stream, pt);
    store_pt.put("version", version_);
    store_pt.put("validated_hash", validated_hash_.encode_to_hex());
    store_pt.put("next_validator_hash", next_validator_hash_.encode_to_hex());
    pt.add_child("store_addtion", store_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::ValidatorUnitStore::DeSerializeJson(const std::string &json){
  boost::property_tree::ptree pt;
  std::stringstream stream(json);
  boost::property_tree::read_json(stream, pt);
  try{
    version_ = pt.get<uint32_t>("store_addtion.version");
    if(version_ == 0x00000001){
      //deserialize other addtion
      validated_hash_.decode_from_hex(pt.get<std::string>("store_addtion.validated_hash"));
      next_validator_hash_.decode_from_hex(pt.get<std::string>("store_addtion.next_validator_hash"));
    }
    unit_ = std::make_shared<core::ValidatorUnit>();
    if(!unit_->DeSerializeJson(json)){
      return false;
    }
  }catch(...){
    return false;
  }
  return true;
}

std::vector<uint8_t> ambr::store::ValidatorUnitStore::SerializeByte() const{
  assert(unit_);
  std::vector<uint8_t> rtn = unit_->SerializeByte();
  uint32_t len=rtn.size();
  std::vector<uint8_t> len_buf;
  len_buf.resize(sizeof(len));
  memcpy(len_buf.data(),&len,sizeof(len));
  rtn.insert(rtn.begin(),len_buf.begin(),len_buf.end());
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  rtn.insert(rtn.end(), validated_hash_.bytes().begin(), validated_hash_.bytes().end());
  rtn.insert(rtn.end(), next_validator_hash_.bytes().begin(), next_validator_hash_.bytes().end());
  return rtn;
}

bool ambr::store::ValidatorUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::ValidatorUnit>();
  uint32_t len;
  memcpy(&len,buf.data(),sizeof(len));
  std::vector<uint8_t> unit_buf;
  unit_buf.resize(len);
  memcpy(unit_buf.data(),buf.data()+sizeof(len),len);
  if(!unit_->DeSerializeByte(unit_buf)){
    return false;
  }

  size_t used_count = len+sizeof(len);
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)+sizeof(validated_hash_)){
      return false;
    }
    memcpy(&validated_hash_, src, sizeof(validated_hash_));
    src += sizeof(validated_hash_);
    memcpy(&next_validator_hash_, src, sizeof(next_validator_hash_));
    return true;
  }//else if(other version)
  return false;
}

std::shared_ptr<ambr::core::Unit> ambr::store::ValidatorUnitStore::GetUnit(){
  return unit_;
}

ambr::core::UnitHash ambr::store::ValidatorUnitStore::next_validator_hash(){
  return next_validator_hash();
}

void ambr::store::ValidatorUnitStore::set_next_validator_hash(const ambr::core::UnitHash &unit_hash){
  next_validator_hash_ = unit_hash;
}
//=========================

ambr::store::EnterValidatorSetUnitStore::EnterValidatorSetUnitStore(std::shared_ptr<core::EnterValidateSetUint> unit):
  UnitStore(ST_EnterValidatorSet),
  unit_(unit){
  //assert(unit);
}

std::shared_ptr<ambr::core::EnterValidateSetUint> ambr::store::EnterValidatorSetUnitStore::unit(){
  return unit_;
}

std::string ambr::store::EnterValidatorSetUnitStore::SerializeJson() const{
  assert(unit_);
  boost::property_tree::ptree pt;
  boost::property_tree::ptree store_pt;
  std::stringstream stream(unit_->SerializeJson());
  try{
    boost::property_tree::read_json(stream, pt);
    store_pt.put("version", version_);
    store_pt.put("validated_hash", validated_hash_.encode_to_hex());
    pt.add_child("store_addtion", store_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::EnterValidatorSetUnitStore::DeSerializeJson(const std::string &json){
  boost::property_tree::ptree pt;
  std::stringstream stream(json);
  boost::property_tree::read_json(stream, pt);
  try{
    version_ = pt.get<uint32_t>("store_addtion.version");
    if(version_ == 0x00000001){
      //deserialize other addtion
      validated_hash_.decode_from_hex(pt.get<std::string>("store_addtion.validated_hash"));
    }
    unit_ = std::make_shared<core::EnterValidateSetUint>();
    if(!unit_->DeSerializeJson(json)){
      return false;
    }
  }catch(...){
    return false;
  }
  return true;
}

std::vector<uint8_t> ambr::store::EnterValidatorSetUnitStore::SerializeByte() const{
  assert(unit_);
  std::vector<uint8_t> rtn = unit_->SerializeByte();
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  rtn.insert(rtn.end(), (uint8_t*)&type_, (uint8_t*)&type_+sizeof(type_));
  rtn.insert(rtn.end(), validated_hash_.bytes().begin(), validated_hash_.bytes().end());
  return rtn;
}

bool ambr::store::EnterValidatorSetUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::EnterValidateSetUint>();
  size_t used_count = 0;
  std::vector<uint8_t> buf_new;
  buf_new.resize(buf.size() -  sizeof(version_)-sizeof(type_) -sizeof(validated_hash_));
  memcpy(buf_new.data(), buf.data(), buf_new.size());
  if(!unit_->DeSerializeByte(buf_new, &used_count)){
    return false;
  }
  used_count = buf_new.size();
  if(buf.size()-used_count < sizeof(version_)){
    return false;
  }
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)+sizeof(type_)+sizeof(validated_hash_)){
      return false;
    }
    memcpy(&validated_hash_, src, sizeof(type_));
    src += sizeof(type_);
    memcpy(&validated_hash_, src, sizeof(validated_hash_));
    //deserialize addtion
    return true;
  }//else if(other version)
  return false;
}

std::shared_ptr<ambr::core::Unit> ambr::store::EnterValidatorSetUnitStore::GetUnit(){
  return unit_;
}

ambr::store::LeaveValidatorSetUnitStore::LeaveValidatorSetUnitStore(std::shared_ptr<core::LeaveValidateSetUint> unit):
  UnitStore(ST_LeaveValidatorSet),
  unit_(unit){
  //assert(unit);
}

std::shared_ptr<ambr::core::LeaveValidateSetUint> ambr::store::LeaveValidatorSetUnitStore::unit(){
  return unit_;
}

std::string ambr::store::LeaveValidatorSetUnitStore::SerializeJson() const{
  assert(unit_);
  boost::property_tree::ptree pt;
  boost::property_tree::ptree store_pt;
  std::stringstream stream(unit_->SerializeJson());
  try{
    boost::property_tree::read_json(stream, pt);
    store_pt.put("version", version_);
    store_pt.put("validated_hash", validated_hash_.encode_to_hex());
    pt.add_child("store_addtion", store_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::LeaveValidatorSetUnitStore::DeSerializeJson(const std::string &json){
  boost::property_tree::ptree pt;
  std::stringstream stream(json);
  boost::property_tree::read_json(stream, pt);
  try{
    version_ = pt.get<uint32_t>("store_addtion.version");
    if(version_ == 0x00000001){
      //deserialize other addtion
      validated_hash_.decode_from_hex(pt.get<std::string>("store_addtion.validated_hash"));
    }
    unit_ = std::make_shared<core::LeaveValidateSetUint>();
    if(!unit_->DeSerializeJson(json)){
      return false;
    }
  }catch(...){
    return false;
  }
  return true;
}

std::vector<uint8_t> ambr::store::LeaveValidatorSetUnitStore::SerializeByte() const{
  assert(unit_);
  std::vector<uint8_t> rtn = unit_->SerializeByte();
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  rtn.insert(rtn.end(), (uint8_t*)&type_, (uint8_t*)&type_+sizeof(type_));
  rtn.insert(rtn.end(), validated_hash_.bytes().begin(), validated_hash_.bytes().end());

  return rtn;
}

bool ambr::store::LeaveValidatorSetUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::LeaveValidateSetUint>();
  size_t used_count = 0;
  std::vector<uint8_t> buf_new;
  buf_new.resize(buf.size()-sizeof(version_)-sizeof(type_)-sizeof(validated_hash_));
  memcpy(buf_new.data(), buf.data(), buf_new.size());
  if(!unit_->DeSerializeByte(buf_new, &used_count)){
    return false;
  }
  used_count = buf_new.size();
  if(buf.size()-used_count < sizeof(version_)){
    return false;
  }
  //deserialize addtion
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)+sizeof(type_  )+sizeof(validated_hash_)){
      return false;
    }
    memcpy(&type_, src, sizeof(type_));
    src += sizeof(type_);
    memcpy(&validated_hash_, src, sizeof(validated_hash_));

    return true;
  }//else if(other version)
  return false;
}

std::shared_ptr<ambr::core::Unit> ambr::store::LeaveValidatorSetUnitStore::GetUnit(){
  return unit_;
}

std::string ambr::store::ValidatorItem::SerializeJson() const{
  boost::property_tree::ptree pt;
  boost::property_tree::ptree child_pt;
  try{
    child_pt.put("validator_hash", validator_public_key_.encode_to_hex());
    child_pt.put("balance", balance_.encode_to_hex());
    child_pt.put("enter_nonce", enter_nonce_);
    child_pt.put("leave_nonce", leave_nonce_);
    pt.put_child("ValidatorItem", child_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::ValidatorItem::DeSerializeJson(const std::string &json){
  try{
    boost::property_tree::ptree pt;
    std::stringstream stream(json);
    boost::property_tree::read_json(stream, pt);
    validator_public_key_.decode_from_hex(pt.get<std::string>("ValidatorItem.validator_hash"));
    balance_.decode_from_hex(pt.get<std::string>("ValidatorItem.balance"));
    enter_nonce_ = pt.get<uint64_t>("ValidatorItem.enter_nonce");
    leave_nonce_ = pt.get<uint64_t>("ValidatorItem.leave_nonce");
    return true;
  }catch(...){
    return false;
  }
}

bool ambr::store::ValidatorItem::operator ==(const ambr::store::ValidatorItem &it) const{
  if(memcmp(this, &it, sizeof(ambr::store::ValidatorItem))){
    return false;
  }
  return true;
}

uint32_t ambr::store::ValidatorSetStore::version() const{
  return version_;
}

void ambr::store::ValidatorSetStore::set_version(uint32_t version){
  version_ = version;
}

std::list<ambr::store::ValidatorItem> ambr::store::ValidatorSetStore::validator_list() const{
  return validator_list_;
}

void ambr::store::ValidatorSetStore::set_validator_list(const std::list<ambr::store::ValidatorItem> &item){
  validator_list_ = item;
}

uint64_t ambr::store::ValidatorSetStore::current_nonce(){
  return current_nonce_;
}

void ambr::store::ValidatorSetStore::set_current_nonce(uint64_t nonce){
  current_nonce_ = nonce;
}

ambr::core::PublicKey ambr::store::ValidatorSetStore::current_validator(){
  return current_validator_;
}

void ambr::store::ValidatorSetStore::set_current_validator(const ambr::core::PublicKey &pub_key){
  current_validator_ = pub_key;
}

void ambr::store::ValidatorSetStore::JoinValidator(const ambr::store::ValidatorItem &item){
  validator_list_.push_back(item);
}

void ambr::store::ValidatorSetStore::LeaveValidator(const ambr::core::PublicKey &pub_key, uint64_t leave_nonce){
  for(std::list<ValidatorItem>::iterator iter = validator_list_.begin();
    iter != validator_list_.end(); iter++){
    if(iter->validator_public_key_ == pub_key){
      iter->leave_nonce_ = leave_nonce;
    }
  }
}

bool ambr::store::ValidatorSetStore::GetValidator(const ambr::core::PublicKey &pub_key, ambr::store::ValidatorItem &item){
  for(ValidatorItem validator_item: validator_list_){
    if(validator_item.validator_public_key_ == pub_key){
      item = validator_item;
      return true;
    }
  }
  return false;
}

std::vector<ambr::core::PublicKey> ambr::store::ValidatorSetStore::GetValidatorList(uint64_t now_nonce){
  std::vector<ambr::core::PublicKey> rtn;
  for(const ValidatorItem& item: validator_list_){
    if(item.enter_nonce_ <= now_nonce &&
       (item.leave_nonce_ > now_nonce || item.leave_nonce_ == 0)){
      rtn.push_back(item.validator_public_key_);
    }
  }
  return rtn;
}

bool ambr::store::ValidatorSetStore::IsValidator(const ambr::core::PublicKey &pub_key, uint64_t now_nonce){
  for(const ValidatorItem& item: validator_list_){
    if(item.validator_public_key_ == pub_key &&
       item.enter_nonce_ <= now_nonce &&
       (item.leave_nonce_ > now_nonce || item.leave_nonce_ == 0)){
      return true;
    }
  }
  return false;
}

bool ambr::store::ValidatorSetStore::IsValidator(const ambr::core::PublicKey &pub_key)
{
  for(const ValidatorItem& item: validator_list_){
    if(item.validator_public_key_ == pub_key){
      return true;
    }
  }
  return false;
}

std::string ambr::store::ValidatorSetStore::SerializeJson() const{
  boost::property_tree::ptree pt;
  try{
    boost::property_tree::ptree pt_child;
    for(ValidatorItem item: validator_list_){
      boost::property_tree::ptree pt_tmp;
      std::string str_tmp = item.SerializeJson();
      pt_tmp.put("",str_tmp);
      pt_child.push_back(std::make_pair("", pt_tmp));
    }
    pt.put("version", version_);
    pt.put("current_nonce", current_nonce_);
    pt.put("current_validator", current_validator_.encode_to_hex());
    pt.put_child("Validators", pt_child);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::ValidatorSetStore::DeSerializeJson(const std::string &json){
  validator_list_.clear();
  try{
    ::boost::property_tree::ptree pt;
    std::istringstream stream(json.c_str());
    ::boost::property_tree::read_json(stream, pt);
    ::boost::property_tree::ptree pt_array;
    version_ = pt.get<uint32_t>("version");
    current_nonce_ = pt.get<uint64_t>("current_nonce");
    current_validator_.decode_from_hex(pt.get<std::string>("current_validator"));
    pt_array = pt.get_child("Validators");
    for(auto child: pt_array){
      ValidatorItem item;
      item.DeSerializeJson(child.second.data());
      validator_list_.push_back(item);
    }
  }catch(...){
    return false;
  }
  return true;
}

std::vector<uint8_t> ambr::store::ValidatorSetStore::SerializeByte() const{
  size_t len = sizeof(version_)+sizeof(current_nonce_)+sizeof(current_validator_)+validator_list_.size()*sizeof(ValidatorItem);
  std::vector<uint8_t> rtn(len);
  uint8_t* dest = rtn.data();

  memcpy(dest, &version_, sizeof(version_));
  dest += sizeof(version_);
  memcpy(dest, &current_nonce_, sizeof(current_nonce_));
  dest += sizeof(current_nonce_);
  memcpy(dest, &current_validator_, sizeof(current_validator_));
  dest += sizeof(current_validator_);

  for(ValidatorItem item: validator_list_){
    memcpy(dest, &item, sizeof(item));
    dest += sizeof(item);
  }
  return rtn;
}

bool ambr::store::ValidatorSetStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  validator_list_.clear();
  size_t min_size = sizeof(version_)+sizeof(current_nonce_)+sizeof(current_validator_);
  if(buf.size() <  min_size|| (buf.size()-min_size)%sizeof(ValidatorItem) != 0){
    return false;
  }
  size_t item_size = (buf.size()-4)/sizeof(ValidatorItem);
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  memcpy(&current_nonce_, src, sizeof(current_nonce_));
  src += sizeof(current_nonce_);
  memcpy(&current_validator_, src, sizeof(current_validator_));
  src += sizeof(current_validator_);
  for(size_t i = 0; i < item_size; i++){
    ValidatorItem item;
    memcpy(&item, src, sizeof(item));
    src+= sizeof(item);
    validator_list_.push_back(item);
  }
  return true;
}

void ambr::store::ValidatorSetStore::Update(uint64_t now_nonce){
  //std::list<ValidatorItem> validator_list_;
  std::list<std::list<ValidatorItem>::iterator> rm_list;
  for(std::list<ValidatorItem>::iterator iter = validator_list_.begin(); iter != validator_list_.end(); iter++){
    if(iter->leave_nonce_ != 0 && iter->leave_nonce_ <= now_nonce){
      rm_list.push_back(iter);
    }
  }
  for(std::list<ValidatorItem>::iterator iter: rm_list){
    validator_list_.erase(iter);
  }
}

bool ambr::store::ValidatorSetStore::GetNonceTurnValidator(uint64_t nonce, core::PublicKey& pub_key){
  std::vector<ambr::core::PublicKey> pub_key_list = GetValidatorList(nonce);
  if(current_nonce_ >= nonce){
    return false;
  }
  uint64_t distance = nonce-current_nonce_;
  uint64_t from_first = 0;
  for(size_t i = 0; i < pub_key_list.size(); i++){
    if(pub_key_list[i] == pub_key){
      from_first = i;
      break;
    }
  }
  uint64_t idx = (distance+from_first)%pub_key_list.size();
  pub_key = pub_key_list[idx];
  return true;
}



ambr::store::ValidatorBalanceStore::ValidatorBalanceStore(){

}

ambr::store::ValidatorBalanceStore::ValidatorBalanceStore(
    const ambr::core::UnitHash& last_update_by,
    const ambr::core::Amount& balance):balance_(balance), last_update_by_(last_update_by){
}

std::string ambr::store::ValidatorBalanceStore::SerializeByte(){
  std::string str_rtn;
  str_rtn.append((const char*)&balance_, sizeof(balance_));
  str_rtn.append((const char*)&last_update_by_, sizeof(last_update_by_));
  return str_rtn;
}

bool ambr::store::ValidatorBalanceStore::DeSerializeByte(const std::string &buf){
  if(buf.size() == sizeof(*this)){
    memcpy(this, buf.data(), buf.size());
    return true;
  }
  return false;
}
