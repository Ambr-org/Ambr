/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include "unit.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <crypto/sha256.h>



std::shared_ptr<ambr::core::Unit> ambr::core::Unit::CreateUnitByByte(const std::vector<uint8_t> &buf){
  //MakeShared TODO
  std::shared_ptr<ReceiveUnit> receive_unit = std::shared_ptr<ReceiveUnit>(new ReceiveUnit());
  std::shared_ptr<SendUnit> send_unit = std::shared_ptr<SendUnit>(new SendUnit());
  if(receive_unit->DeSerializeByte(buf)){
    return receive_unit;
  }else if(send_unit->DeSerializeByte(buf)){
    return send_unit;
  }
  return std::shared_ptr<ambr::core::Unit>();
}

ambr::core::Unit::Unit():
  version_(0),
  type_(UnitType::Invalidate),
  public_key_("0"),
  prev_unit_("0"),
  balance_("0"),
  hash_("0"),
  sign_("0"){
}

ambr::core::SendUnit::SendUnit():Unit(){

}

std::string ambr::core::SendUnit::SerializeJson() const{
  ::boost::property_tree::ptree unit_pt;
  unit_pt.put("version", version_);
  unit_pt.put("type", (uint8_t)type_);
  unit_pt.put("public_key", public_key_.encode_to_hex());
  unit_pt.put("prev_unit", prev_unit_.encode_to_hex());
  unit_pt.put("balance", balance_.encode_to_hex());
  unit_pt.put("hash", hash_.encode_to_hex());
  unit_pt.put("sign", sign_.encode_to_hex());
  unit_pt.put("dest", dest_.encode_to_hex());
  ::boost::property_tree::ptree pt;
  pt.add_child("unit", unit_pt);
  ::std::ostringstream stream;
  ::boost::property_tree::write_json(stream, pt);
  return stream.str();
}

bool ambr::core::SendUnit::DeSerializeJson(const std::string& json){
  try{
    ::boost::property_tree::ptree pt;
    std::istrstream stream(json.c_str());
    ::boost::property_tree::read_json(stream, pt);
    version_ = pt.get<uint32_t>("unit.version");
    type_ = (UnitType)pt.get<uint8_t>("unit.type");
    public_key_.decode_from_hex(pt.get<std::string>("unit.public_key"));
    prev_unit_.decode_from_hex(pt.get<std::string>("unit.prev_unit"));
    balance_.decode_from_hex(pt.get<std::string>("unit.balance"));
    hash_.decode_from_hex(pt.get<std::string>("unit.hash"));
    sign_.decode_from_hex(pt.get<std::string>("unit.sign"));
    dest_.decode_from_hex(pt.get<std::string>("unit.dest"));
    return true;
  }catch(::boost::property_tree::json_parser::json_parser_error& error){
    std::cout<<error.message();
    return false;
  }
}

std::vector<uint8_t> ambr::core::SendUnit::SerializeByte( ) const {
  std::vector<uint8_t> buf;
  if(version_ == 0x00000001){
    uint32_t len = sizeof(version_)+sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(dest_);
    buf.resize(len);

    uint8_t* dest = buf.data();
    memcpy(dest, &version_, sizeof(version_));
    dest += sizeof(version_);

    memcpy(dest, &type_, sizeof(type_));
    dest += sizeof(type_);

    memcpy(dest, &public_key_, sizeof(public_key_));
    dest += sizeof(public_key_);

    memcpy(dest, &prev_unit_, sizeof(prev_unit_));
    dest += sizeof(prev_unit_);

    memcpy(dest, &balance_, sizeof(balance_));
    dest += sizeof(balance_);

    memcpy(dest, &hash_, sizeof(hash_));
    dest += sizeof(hash_);

    memcpy(dest, &sign_, sizeof(sign_));
    dest += sizeof(sign_);

    memcpy(dest, &dest_, sizeof(dest_));
    dest += sizeof(dest_);
  }
  return buf;
}

bool ambr::core::SendUnit::DeSerializeByte(const std::vector<uint8_t> &buf){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(dest_);
    if(buf.size() == len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

      memcpy(&public_key_, src, sizeof(public_key_));
      src += sizeof(public_key_);

      memcpy(&prev_unit_, src, sizeof(prev_unit_));
      src += sizeof(prev_unit_);

      memcpy(&balance_, src, sizeof(balance_));
      src += sizeof(balance_);

      memcpy(&hash_, src, sizeof(hash_));
      src += sizeof(hash_);

      memcpy(&sign_, src, sizeof(sign_));
      src += sizeof(sign_);

      memcpy(&dest_, src, sizeof(dest_));
      src += sizeof(dest_);
      return true;
    }
  }
  return false;
}

ambr::core::UnitHash ambr::core::SendUnit::CalcHash() const {
  crypto::SHA256OneByOneHasher hasher;
  hasher.init();
  hasher.process(version_);
  hasher.process(type_);
  hasher.process(public_key_);
  hasher.process(prev_unit_);
  hasher.process(balance_);
  hasher.process(dest_);
  hasher.finish();
  UnitHash::ArrayType array;
  hasher.get_hash_bytes(array.begin(), array.end());
  return UnitHash(array);
}

void ambr::core::SendUnit::CalcHashAndFill(){
  hash_ = CalcHash();
}

bool ambr::core::SendUnit::SignatureAndFill(const ambr::core::PrivateKey &key){
  //TODO:
  Signature::ArrayType array_sign;
  PrivateKey::ArrayType array_key;
  for(int i = 0; i< array_key.size(); i++){
    array_key = key.bytes();
    array_sign[i]=array_key[i];
  }
  sign_.set_bytes(array_sign);
  return true;
}

bool ambr::core::SendUnit::Validate(std::string *err) const{
  //check version
  if(version_ != 0x00000001){
    if(err){
      *err = "error version";
    }
    return false;
  }
  //check hash
  if(hash_ != CalcHash()){
    if(err){
      *err = "error hash";
    }
    return false;
  }
  //check signature
  //TODO:
  return true;
}

ambr::core::ReceiveUnit::ReceiveUnit():Unit(){

}

std::string ambr::core::ReceiveUnit::SerializeJson() const{
  ::boost::property_tree::ptree unit_pt;
  unit_pt.put("version", version_);
  unit_pt.put("type", (uint8_t)type_);
  unit_pt.put("public_key", public_key_.encode_to_hex());
  unit_pt.put("prev_unit", prev_unit_.encode_to_hex());
  unit_pt.put("balance", balance_.encode_to_hex());
  unit_pt.put("hash", hash_.encode_to_hex());
  unit_pt.put("sign", sign_.encode_to_hex());
  unit_pt.put("from", from_.encode_to_hex());
  ::boost::property_tree::ptree pt;
  pt.add_child("unit", unit_pt);
  ::std::ostringstream stream;
  ::boost::property_tree::write_json(stream, pt);
  return stream.str();
}

bool ambr::core::ReceiveUnit::DeSerializeJson(const std::string &json){
  try{
    ::boost::property_tree::ptree pt;
    std::istrstream stream(json.c_str());
    ::boost::property_tree::read_json(stream, pt);
    version_ = pt.get<uint32_t>("unit.version");
    type_ = (UnitType)pt.get<uint8_t>("unit.type");
    public_key_.decode_from_hex(pt.get<std::string>("unit.public_key"));
    prev_unit_.decode_from_hex(pt.get<std::string>("unit.prev_unit"));
    balance_.decode_from_hex(pt.get<std::string>("unit.balance"));
    hash_.decode_from_hex(pt.get<std::string>("unit.hash"));
    sign_.decode_from_hex(pt.get<std::string>("unit.sign"));
    from_.decode_from_hex(pt.get<std::string>("unit.from"));
    return true;
  }catch(::boost::property_tree::json_parser::json_parser_error& error){
    std::cout<<error.message();
    return false;
  }
}

std::vector<uint8_t> ambr::core::ReceiveUnit::SerializeByte() const{
  std::vector<uint8_t> buf;
  if(version_ == 0x00000001){
    uint32_t len = sizeof(version_)+sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(from_);
    buf.resize(len);

    uint8_t* dest = buf.data();
    memcpy(dest, &version_, sizeof(version_));
    dest += sizeof(version_);

    memcpy(dest, &type_, sizeof(type_));
    dest += sizeof(type_);

    memcpy(dest, &public_key_, sizeof(public_key_));
    dest += sizeof(public_key_);

    memcpy(dest, &prev_unit_, sizeof(prev_unit_));
    dest += sizeof(prev_unit_);

    memcpy(dest, &balance_, sizeof(balance_));
    dest += sizeof(balance_);

    memcpy(dest, &hash_, sizeof(hash_));
    dest += sizeof(hash_);

    memcpy(dest, &sign_, sizeof(sign_));
    dest += sizeof(sign_);

    memcpy(dest, &from_, sizeof(from_));
    dest += sizeof(from_);
  }
  return buf;
}

bool ambr::core::ReceiveUnit::DeSerializeByte(const std::vector<uint8_t> &buf){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(from_);
    if(buf.size() == len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

      if(type_ != UnitType::receive){
        return false;
      }

      if(type_ != UnitType::send){
        return false;
      }

      memcpy(&public_key_, src, sizeof(public_key_));
      src += sizeof(public_key_);

      memcpy(&prev_unit_, src, sizeof(prev_unit_));
      src += sizeof(prev_unit_);

      memcpy(&balance_, src, sizeof(balance_));
      src += sizeof(balance_);

      memcpy(&hash_, src, sizeof(hash_));
      src += sizeof(hash_);

      memcpy(&sign_, src, sizeof(sign_));
      src += sizeof(sign_);

      memcpy(&from_, src, sizeof(from_));
      src += sizeof(from_);
      return true;
    }
  }
  return false;
}

ambr::core::UnitHash ambr::core::ReceiveUnit::CalcHash() const {
  crypto::SHA256OneByOneHasher hasher;
  hasher.init();
  hasher.process(version_);
  hasher.process(type_);
  hasher.process(public_key_);
  hasher.process(prev_unit_);
  hasher.process(balance_);
  hasher.process(from_);
  hasher.finish();
  UnitHash::ArrayType array;
  hasher.get_hash_bytes(array.begin(), array.end());
  return UnitHash(array);
}

void ambr::core::ReceiveUnit::CalcHashAndFill(){
  hash_ = CalcHash();
}

bool ambr::core::ReceiveUnit::SignatureAndFill(const ambr::core::PrivateKey &key){
  //TODO:
  Signature::ArrayType array_sign;
  PrivateKey::ArrayType array_key;
  for(int i = 0; i< array_key.size(); i++){
    array_sign[i]=array_key[i];
  }
  sign_.set_bytes(array_sign);
  return true;
}

bool ambr::core::ReceiveUnit::Validate(std::string *err) const{
  //check version
  if(version_ != 0x00000001){
    if(err){
      *err = "error version";
    }
    return false;
  }
  //check hash
  if(hash_ != CalcHash()){
    if(err){
      *err = "error hash";
    }
    return false;
  }
  //check signature
  //TODO:
  return true;
}
