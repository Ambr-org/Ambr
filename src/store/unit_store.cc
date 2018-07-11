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

ambr::store::SendUnitStore::SendUnitStore(std::shared_ptr<core::SendUnit> unit):UnitStore(ST_SendUnit), unit_(unit), version_(0x00000001){
  assert(unit);
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

uint32_t ambr::store::SendUnitStore::version(){
  return version_;
}

void ambr::store::SendUnitStore::set_version(uint32_t version){
  version_ = version;
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
    pt.add_child("store_addtion", store_pt);
  }catch(...){
    assert(1);
  }
  std::ostringstream out_stream;
  boost::property_tree::write_json(out_stream, pt);
  return out_stream.str();
}

bool ambr::store::SendUnitStore::DeSerializeJson(const std::string &json){
  boost::property_tree::ptree pt;
  std::stringstream stream(json);
  boost::property_tree::read_json(stream, pt);
  try{
    version_ = pt.get<uint32_t>("store_addtion.version");
    if(version_ == 0x00000001){
      receive_unit_hash_.decode_from_hex(pt.get<std::string>("store_addtion.receive_unit_hash"));
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
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  rtn.insert(rtn.end(),receive_unit_hash_.bytes().begin(), receive_unit_hash_.bytes().end());
  return rtn;
}

bool ambr::store::SendUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::SendUnit>();
  size_t used_count = 0;
  if(!unit_->DeSerializeByte(buf, &used_count)){
    return false;
  }
  if(buf.size()-used_count < sizeof(version_)){
    return false;
  }
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)+sizeof(receive_unit_hash_)){
      return false;
    }
    memcpy(&receive_unit_hash_, src, sizeof(receive_unit_hash_));
    return true;
  }//else if(other version)
  return false;
}


ambr::store::ReceiveUnitStore::ReceiveUnitStore(std::shared_ptr<core::ReceiveUnit> unit):UnitStore(ST_ReceiveUnit), unit_(unit), version_(0x00000001){
  assert(unit);
}

std::shared_ptr<ambr::core::ReceiveUnit> ambr::store::ReceiveUnitStore::unit(){
  return unit_;
}

uint32_t ambr::store::ReceiveUnitStore::version(){
  return version_;
}

void ambr::store::ReceiveUnitStore::set_version(uint32_t version){
  version_ = version;
}

std::string ambr::store::ReceiveUnitStore::SerializeJson() const{
  assert(unit_);
  boost::property_tree::ptree pt;
  boost::property_tree::ptree store_pt;
  std::stringstream stream(unit_->SerializeJson());
  try{
    boost::property_tree::read_json(stream, pt);
    store_pt.put("version", version_);
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
  rtn.insert(rtn.end(), (uint8_t*)&version_, (uint8_t*)&version_+sizeof(version_));
  return rtn;
}

bool ambr::store::ReceiveUnitStore::DeSerializeByte(const std::vector<uint8_t> &buf){
  unit_ = std::make_shared<core::ReceiveUnit>();
  size_t used_count = 0;
  if(!unit_->DeSerializeByte(buf, &used_count)){
    return false;
  }
  if(buf.size()-used_count < sizeof(version_)){
    return false;
  }
  const uint8_t* src = &buf[used_count];
  memcpy(&version_, src, sizeof(version_));
  src += sizeof(version_);
  if(version_ == 0x00000001){
    if(buf.size()-used_count < sizeof(version_)){
      return false;
    }
    //deserialize addtion
    return true;
  }//else if(other version)
  return false;

}


