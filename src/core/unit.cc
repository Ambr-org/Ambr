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
    std::istringstream stream(json.c_str());
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

bool ambr::core::SendUnit::DeSerializeByte(const std::vector<uint8_t> &buf, size_t* used_size){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(dest_);
    if(buf.size() >= len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

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

      memcpy(&dest_, src, sizeof(dest_));
      src += sizeof(dest_);
      if(used_size)*used_size=len;
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
  sign_ = GetSignByPrivateKey(hash_.bytes().data(), hash_.bytes().size(), key);
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
  if(!ambr::core::SignIsValidate(hash_.bytes().data(), hash_.bytes().size(), public_key_, sign_)){
    *err = "error signature";
    return false;
  }
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
    std::istringstream stream(json.c_str());
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

bool ambr::core::ReceiveUnit::DeSerializeByte(const std::vector<uint8_t> &buf, size_t* used_count){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(from_);
    if(buf.size() >= len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

      if(type_ != UnitType::receive){
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
      if(used_count)*used_count = len;
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
  for(size_t i = 0; i< array_key.size(); i++){
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

ambr::core::VoteUnit::VoteUnit():Unit(){

}

std::string ambr::core::VoteUnit::SerializeJson() const{
  ::boost::property_tree::ptree unit_pt;
  unit_pt.put("version", version_);
  unit_pt.put("type", (uint8_t)type_);
  unit_pt.put("public_key", public_key_.encode_to_hex());
  unit_pt.put("prev_unit", prev_unit_.encode_to_hex());
  unit_pt.put("balance", balance_.encode_to_hex());
  unit_pt.put("hash", hash_.encode_to_hex());
  unit_pt.put("sign", sign_.encode_to_hex());
  unit_pt.put("validator_unit_hash", validator_unit_hash_.encode_to_hex());
  unit_pt.put("accept", accept_);
  ::boost::property_tree::ptree pt;
  pt.add_child("unit", unit_pt);
  ::std::ostringstream stream;
  ::boost::property_tree::write_json(stream, pt);
  return stream.str();
}

bool ambr::core::VoteUnit::DeSerializeJson(const std::string& json){
  try{
    ::boost::property_tree::ptree pt;
    std::istringstream stream(json.c_str());
    ::boost::property_tree::read_json(stream, pt);
    version_ = pt.get<uint32_t>("unit.version");
    type_ = (UnitType)pt.get<uint8_t>("unit.type");
    public_key_.decode_from_hex(pt.get<std::string>("unit.public_key"));
    prev_unit_.decode_from_hex(pt.get<std::string>("unit.prev_unit"));
    balance_.decode_from_hex(pt.get<std::string>("unit.balance"));
    hash_.decode_from_hex(pt.get<std::string>("unit.hash"));
    sign_.decode_from_hex(pt.get<std::string>("unit.sign"));
    validator_unit_hash_.decode_from_hex(pt.get<std::string>("unit.validator_unit_hash"));
    accept_ = (uint8_t)pt.get<uint8_t>("unit.accept");
    return true;
  }catch(::boost::property_tree::json_parser::json_parser_error& error){
    std::cout<<error.message();
    return false;
  }
}

std::vector<uint8_t> ambr::core::VoteUnit::SerializeByte() const{
  std::vector<uint8_t> buf;
  if(version_ == 0x00000001){
    uint32_t len = sizeof(version_)+sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(validator_unit_hash_)+sizeof(accept_);
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
    memcpy(dest, &validator_unit_hash_, sizeof(validator_unit_hash_));
    dest += sizeof(validator_unit_hash_);

    memcpy(dest, &accept_, sizeof(accept_));
  }
  return buf;
}

bool ambr::core::VoteUnit::DeSerializeByte(const std::vector<uint8_t> &buf, size_t* used_size){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(validator_unit_hash_)+sizeof(accept_);
    if(buf.size() >= len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

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

      memcpy(&validator_unit_hash_, src, sizeof(validator_unit_hash_));
      src += sizeof(validator_unit_hash_);

      memcpy(&accept_, src, sizeof(accept_));
      src += sizeof(accept_);

      if(used_size)*used_size=len;
      return true;
    }
  }
  return false;
}

ambr::core::UnitHash ambr::core::VoteUnit::CalcHash() const {
  crypto::SHA256OneByOneHasher hasher;
  hasher.init();
  hasher.process(version_);
  hasher.process(type_);
  hasher.process(public_key_);
  hasher.process(prev_unit_);
  hasher.process(balance_);
  hasher.process(validator_unit_hash_);
  hasher.process(accept_);
  hasher.finish();
  UnitHash::ArrayType array;
  hasher.get_hash_bytes(array.begin(), array.end());
  return UnitHash(array);
}

void ambr::core::VoteUnit::CalcHashAndFill(){
  hash_ = CalcHash();
}

bool ambr::core::VoteUnit::SignatureAndFill(const ambr::core::PrivateKey &key){
  sign_ = GetSignByPrivateKey(hash_.bytes().data(), hash_.bytes().size(), key);
  return true;
}

bool ambr::core::VoteUnit::Validate(std::string *err) const{
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
  if(!ambr::core::SignIsValidate(hash_.bytes().data(), hash_.bytes().size(), public_key_, sign_)){
    *err = "error signature";
    return false;
  }
  return true;
}


ambr::core::ValidatorUnit::ValidatorUnit():Unit(){

}

std::string ambr::core::ValidatorUnit::SerializeJson() const{
  ::boost::property_tree::ptree unit_pt;
  unit_pt.put("version", version_);
  unit_pt.put("type", (uint8_t)type_);
  unit_pt.put("public_key", public_key_.encode_to_hex());
  unit_pt.put("prev_unit", prev_unit_.encode_to_hex());
  unit_pt.put("balance", balance_.encode_to_hex());
  unit_pt.put("hash", hash_.encode_to_hex());
  unit_pt.put("sign", sign_.encode_to_hex());
  ::boost::property_tree::ptree pt_child;
  pt_child.clear();
  for(UnitHash hash:check_list_){
    ::boost::property_tree::ptree tmp;
    tmp.put("", hash.encode_to_hex());
    pt_child.push_back(std::make_pair("", tmp));
  }
  unit_pt.add_child("check_list", pt_child);

  pt_child.clear();
  for(UnitHash hash:vote_hash_list_){
    ::boost::property_tree::ptree tmp;
    tmp.put("", hash.encode_to_hex());
    pt_child.push_back(std::make_pair("", tmp));
  }
  unit_pt.add_child("vote_hash_list", pt_child);

  unit_pt.put("percent", percent_);

  pt_child.clear();
  for(VoteUnit unit:vote_list_){
    ::boost::property_tree::ptree tmp;
    ::boost::property_tree::ptree vote_tree;
    std::istringstream istream(unit.SerializeJson());
    ::boost::property_tree::read_json(istream, vote_tree);
    tmp.put_child("", vote_tree);
    pt_child.push_back(std::make_pair("", tmp));
  }
  unit_pt.add_child("vote_list", pt_child);
  unit_pt.put("time_stamp", time_stamp_);
  unit_pt.put("nonce", nonce_);
  ::boost::property_tree::ptree pt;
  pt.add_child("unit", unit_pt);
  ::std::ostringstream stream;
  ::boost::property_tree::write_json(stream, pt);
  return stream.str();
}

bool ambr::core::ValidatorUnit::DeSerializeJson(const std::string& json){
  try{
    ::boost::property_tree::ptree pt;
    std::istringstream stream(json.c_str());
    ::boost::property_tree::read_json(stream, pt);
    version_ = pt.get<uint32_t>("unit.version");
    type_ = (UnitType)pt.get<uint8_t>("unit.type");
    public_key_.decode_from_hex(pt.get<std::string>("unit.public_key"));
    prev_unit_.decode_from_hex(pt.get<std::string>("unit.prev_unit"));
    balance_.decode_from_hex(pt.get<std::string>("unit.balance"));
    hash_.decode_from_hex(pt.get<std::string>("unit.hash"));
    sign_.decode_from_hex(pt.get<std::string>("unit.sign"));
    ::boost::property_tree::ptree pt_array;
    pt_array = pt.get_child("unit.check_list");
    for(auto child: pt_array){
      UnitHash hash;
      hash.decode_from_hex(child.second.data());
      check_list_.push_back(hash);
    }

    pt_array = pt.get_child("unit.vote_hash_list");
    for(auto child: pt_array){
      UnitHash hash;
      hash.decode_from_hex(child.second.data());
      vote_hash_list_.push_back(hash);
    }

    pt_array = pt.get_child("unit.vote_list");
    for(auto child: pt_array){
      VoteUnit vote_unit;
      vote_unit.DeSerializeJson(child.second.data());
      vote_list_.push_back(vote_unit);
    }
    time_stamp_ = pt.get<time_t>("unit.time_stamp");
    nonce_ = pt.get<uint64_t>("unit.nonce");
    return true;
  }catch(::boost::property_tree::json_parser::json_parser_error& error){
    std::cout<<error.message();
    return false;
  }
}

std::vector<uint8_t> ambr::core::ValidatorUnit::SerializeByte( ) const {
  std::vector<uint8_t> buf;
  if(version_ == 0x00000001){
    uint32_t len = sizeof(version_)+sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+
        sizeof(uint32_t)+sizeof(UnitHash)*check_list_.size()+
        sizeof(uint32_t)+sizeof(UnitHash)*vote_hash_list_.size()+
        sizeof(percent_)+
        sizeof(uint32_t)+(vote_list_.size()?(vote_list_[0].SerializeByte().size()*vote_list_.size()):0)+
        sizeof(time_stamp_)+
        sizeof(nonce_);
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

    uint32_t tmp_len;
    tmp_len = check_list_.size();
    memcpy(dest, &tmp_len, sizeof(tmp_len));
    dest += sizeof(tmp_len);

    for(UnitHash hash: check_list_){
      memcpy(dest, &hash, sizeof(hash));
      dest += sizeof(hash);
    }

    tmp_len = vote_hash_list_.size();
    memcpy(dest, &tmp_len, sizeof(tmp_len));
    dest += sizeof(tmp_len);

    for(UnitHash hash: vote_hash_list_){
      memcpy(dest, &hash, sizeof(hash));
      dest += sizeof(hash);
    }

    memcpy(dest, &percent_, sizeof(percent_));
    dest += sizeof(percent_);

    tmp_len = vote_list_.size();
    memcpy(dest, &tmp_len, sizeof(tmp_len));
    dest += sizeof(tmp_len);
    for(VoteUnit unit: vote_list_){
      std::vector<uint8_t> buf = unit.SerializeByte();
      memcpy(dest, buf.data(), buf.size());
      dest += buf.size();
    }

    memcpy(dest, &time_stamp_, sizeof(time_stamp_));
    dest += sizeof(time_stamp_);

    memcpy(dest, &nonce_, sizeof(nonce_));
    dest += sizeof(nonce_);
  }
  return buf;
}

bool ambr::core::ValidatorUnit::DeSerializeByte(const std::vector<uint8_t> &buf, size_t* used_size){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_)+sizeof(uint32_t)+sizeof(time_stamp_);
    if(buf.size() >= len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

      if(type_ != UnitType::Validator){
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

      const uint8_t* end_point = &buf[buf.size()];
      uint32_t len;
      memcpy(&len, src, sizeof(len));
      src += 4;
      if(end_point - src < len*(uint32_t)sizeof(UnitHash)){
        return false;
      }

      for(uint32_t i = 0; i < len; i++){
        UnitHash hash;
        memcpy(&hash, src, sizeof(hash));
        src += sizeof(hash);
        check_list_.push_back(hash);
      }

      if(end_point - src < (uint32_t)sizeof(uint32_t)){
        return false;
      }
      memcpy(&len, src, sizeof(len));
      src += sizeof(len);

      if(end_point - src < len*(uint32_t)sizeof(UnitHash)){
        return false;
      }

      for(uint32_t i = 0; i < len; i++){
        UnitHash hash;
        memcpy(&hash, src, sizeof(hash));
        src += sizeof(hash);
        vote_hash_list_.push_back(hash);
      }

      if(end_point - src < (uint32_t)sizeof(percent_)){
        return false;
      }
      memcpy(&percent_, src, sizeof(percent_));
      src += sizeof(percent_);

      if(end_point - src < (uint32_t)sizeof(uint32_t)){
        return false;
      }
      memcpy(&len, src, sizeof(len));
      src += sizeof(len);

      VoteUnit tmp;
      uint32_t vote_unit_size = tmp.SerializeByte().size();
      if(end_point - src < vote_unit_size*len){
        return false;
      }
      for(uint32_t i = 0; i < len; i++){
        std::vector<uint8_t> buf;
        buf.assign(src, src+vote_unit_size);
        VoteUnit tmp;
        if(!tmp.DeSerializeByte(buf)){
          return false;
        }
        vote_list_.push_back(tmp);
        src += vote_unit_size;
      }

      memcpy(&time_stamp_, src, sizeof(time_stamp_));
      src += sizeof(time_stamp_);

      memcpy(&nonce_, src, sizeof(nonce_));
      src += sizeof(nonce_);

      if(used_size)*used_size=len;
      return true;
    }
  }
  return false;
}

ambr::core::UnitHash ambr::core::ValidatorUnit::CalcHash() const {
  crypto::SHA256OneByOneHasher hasher;
  hasher.init();
  hasher.process(version_);
  hasher.process(type_);
  hasher.process(public_key_);
  hasher.process(prev_unit_);
  hasher.process(balance_);
  for(UnitHash hash:check_list_){
    hasher.process(hash);
  }
  for(UnitHash hash:vote_hash_list_){
    hasher.process(hash);
  }
  hasher.process(percent_);
  hasher.finish();
  UnitHash::ArrayType array;
  hasher.get_hash_bytes(array.begin(), array.end());
  return UnitHash(array);
}

void ambr::core::ValidatorUnit::CalcHashAndFill(){
  hash_ = CalcHash();
}

bool ambr::core::ValidatorUnit::SignatureAndFill(const ambr::core::PrivateKey &key){
  sign_ = GetSignByPrivateKey(hash_.bytes().data(), hash_.bytes().size(), key);
  return true;
}

bool ambr::core::ValidatorUnit::Validate(std::string *err) const{
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
  if(!ambr::core::SignIsValidate(hash_.bytes().data(), hash_.bytes().size(), public_key_, sign_)){
    *err = "error signature";
    return false;
  }
  return true;
}



ambr::core::EnterValidateSetUint::EnterValidateSetUint():Unit(){

}

std::string ambr::core::EnterValidateSetUint::SerializeJson() const{
  ::boost::property_tree::ptree unit_pt;
  unit_pt.put("version", version_);
  unit_pt.put("type", (uint8_t)type_);
  unit_pt.put("public_key", public_key_.encode_to_hex());
  unit_pt.put("prev_unit", prev_unit_.encode_to_hex());
  unit_pt.put("balance", balance_.encode_to_hex());
  unit_pt.put("hash", hash_.encode_to_hex());
  unit_pt.put("sign", sign_.encode_to_hex());
  ::boost::property_tree::ptree pt;
  pt.add_child("unit", unit_pt);
  ::std::ostringstream stream;
  ::boost::property_tree::write_json(stream, pt);
  return stream.str();
}

bool ambr::core::EnterValidateSetUint::DeSerializeJson(const std::string& json){
  try{
    ::boost::property_tree::ptree pt;
    std::istringstream stream(json.c_str());
    ::boost::property_tree::read_json(stream, pt);
    version_ = pt.get<uint32_t>("unit.version");
    type_ = (UnitType)pt.get<uint8_t>("unit.type");
    public_key_.decode_from_hex(pt.get<std::string>("unit.public_key"));
    prev_unit_.decode_from_hex(pt.get<std::string>("unit.prev_unit"));
    balance_.decode_from_hex(pt.get<std::string>("unit.balance"));
    hash_.decode_from_hex(pt.get<std::string>("unit.hash"));
    sign_.decode_from_hex(pt.get<std::string>("unit.sign"));
    return true;
  }catch(::boost::property_tree::json_parser::json_parser_error& error){
    std::cout<<error.message();
    return false;
  }
}

std::vector<uint8_t> ambr::core::EnterValidateSetUint::SerializeByte( ) const {
  std::vector<uint8_t> buf;
  if(version_ == 0x00000001){
    uint32_t len = sizeof(version_)+sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_);
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
  }
  return buf;
}

bool ambr::core::EnterValidateSetUint::DeSerializeByte(const std::vector<uint8_t> &buf, size_t* used_size){
  if(buf.size() < sizeof(version_)){
    return false;
  }
  const uint8_t* src = buf.data();
  memcpy(&version_, src, sizeof(version_));
  if(version_== 0x00000001){
    uint32_t len = sizeof(version_) + sizeof(type_)+sizeof(public_key_)+sizeof(prev_unit_)+sizeof(balance_)+sizeof(hash_)+sizeof(sign_);
    if(buf.size() >= len){
      memcpy(&version_, src, sizeof(version_));
      src += sizeof(version_);

      memcpy(&type_, src, sizeof(type_));
      src += sizeof(type_);

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
      if(used_size)*used_size=len;
      return true;
    }
  }
  return false;
}

ambr::core::UnitHash ambr::core::EnterValidateSetUint::CalcHash() const {
  crypto::SHA256OneByOneHasher hasher;
  hasher.init();
  hasher.process(version_);
  hasher.process(type_);
  hasher.process(public_key_);
  hasher.process(prev_unit_);
  hasher.process(balance_);
  hasher.finish();
  UnitHash::ArrayType array;
  hasher.get_hash_bytes(array.begin(), array.end());
  return UnitHash(array);
}

void ambr::core::EnterValidateSetUint::CalcHashAndFill(){
  hash_ = CalcHash();
}

bool ambr::core::EnterValidateSetUint::SignatureAndFill(const ambr::core::PrivateKey &key){
  sign_ = GetSignByPrivateKey(hash_.bytes().data(), hash_.bytes().size(), key);
  return true;
}

bool ambr::core::EnterValidateSetUint::Validate(std::string *err) const{
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
  if(!ambr::core::SignIsValidate(hash_.bytes().data(), hash_.bytes().size(), public_key_, sign_)){
    *err = "error signature";
    return false;
  }
  return true;
}
