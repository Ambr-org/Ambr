
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef  AMBR_CORE_UNIT_H_
#define  AMBR_CORE_UNIT_H_
// const function
// const input
// TODO
#include <memory>
#include <utils/uint.h>
#include <core/key.h>
#include <time.h>
#include <vector>
namespace ambr {
namespace core {

namespace boost{
namespace property_tree{
class ptree;
}
}
//no used
class AccountInfo{
public:
  AccountInfo ();
  AccountInfo (AccountInfo const &);
  bool operator== (AccountInfo const &) const;
  bool operator!= (AccountInfo const &) const;
private:
  UnitHash head_;
  UnitHash pre_block_;
  UnitHash open_block;
  Amount balance_;
};

enum class UnitType : uint8_t{
  Invalidate = 0,
  send = 1,
  receive = 2,
  EnterValidateSet = 3,
  Vote = 4,
  Validator = 5
};

class Unit{
public:
  virtual std::string SerializeJson () const = 0;
  virtual bool DeSerializeJson(const std::string& json) = 0;
  virtual std::vector<uint8_t> SerializeByte() const = 0;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf, size_t* used_size) = 0;

  virtual void CalcHashAndFill() = 0;
  virtual bool SignatureAndFill(const PrivateKey& key) = 0;
  virtual bool Validate(std::string* err) const = 0;
public:
  static std::shared_ptr<Unit> CreateUnitByJson(const std::string& json);
  static std::shared_ptr<Unit> CreateUnitByByte(const std::vector<uint8_t>& buf);
public:
  const uint32_t& version(){
    return version_;
  }
  void set_version(uint32_t version){
    version_ = version;
  }

  const UnitType& type(){
    return type_;
  }
  void set_type(UnitType type){
    type_ = type;
  }

  const PublicKey& public_key(){
    return public_key_;
  }
  void set_public_key(const PublicKey& public_key){
    public_key_ = public_key;
  }

  const UnitHash& prev_unit(){
    return prev_unit_;
  }
  void set_prev_unit(const UnitHash& prev_unit){
    prev_unit_ = prev_unit;
  }

  const Amount& balance(){
    return balance_;
  }
  void set_balance(const Amount& amount){
    balance_ = amount;
  }

  const UnitHash& hash(){
    return hash_;
  }
  void set_hash(const UnitHash& hash){
    hash_ = hash;
  }

  const Signature& sign(){
    return sign_;
  }
  void set_sign(const Signature& sign){
    sign_ = sign;
  }
protected:
  uint32_t version_;
  UnitType type_;
  PublicKey public_key_;
  UnitHash prev_unit_;
  Amount balance_;
  UnitHash hash_;
  Signature sign_;
protected:
  Unit();
};

class SendUnit:public Unit{
public:
  SendUnit();
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf, size_t* used_size = nullptr) override;

  UnitHash CalcHash() const;
  virtual void CalcHashAndFill()override;
  virtual bool SignatureAndFill(const PrivateKey& key)override;
  virtual bool Validate(std::string* err) const override;
public:
  const PublicKey& dest(){
    return dest_;
  }
  void set_dest(const PublicKey& dest){
    dest_ = dest;
  }
private:
  PublicKey dest_;
};

class ReceiveUnit:public Unit{
public:
  ReceiveUnit();
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf, size_t* used_size = nullptr) override;

  UnitHash CalcHash() const;
  virtual void CalcHashAndFill() override;
  virtual bool SignatureAndFill(const PrivateKey& key) override;
  virtual bool Validate(std::string* err) const override;
public:
  const UnitHash& from(){
    return from_;
  }
  void set_from(const UnitHash& from){
    from_ = from;
  }
private:
  UnitHash from_;
};

class VoteUnit:public Unit{
public:
  VoteUnit();
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf, size_t* used_size = nullptr) override;

  UnitHash CalcHash() const;
  virtual void CalcHashAndFill() override;
  virtual bool SignatureAndFill(const PrivateKey& key) override;
  virtual bool Validate(std::string* err) const override;
public:
  void SetValidatorUnitHash(const UnitHash& hash){
    validator_unit_hash_ = hash;
  }
  UnitHash ValidatorUnitHash(){
    return validator_unit_hash_;
  }
  void SetAccept(bool accept){
    accept_ = accept;
  }
  bool accept(){
    return accept_;
  }
private:
  UnitHash validator_unit_hash_;
  uint8_t accept_;
};

class ValidatorUnit:public Unit{
public:
  ValidatorUnit();
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf, size_t* used_size = nullptr) override;

  UnitHash CalcHash() const;
  virtual void CalcHashAndFill() override;
  virtual bool SignatureAndFill(const PrivateKey& key) override;
  virtual bool Validate(std::string* err) const override;
public:
  void add_check_list_(const UnitHash& hash){
    check_list_.push_back(hash);
  }
  void set_check_list(const std::vector<UnitHash>& hash_list){
    check_list_ = hash_list;
  }
  std::vector<UnitHash> check_list()const{
    return check_list_;
  }
  void add_vote_hash_list(const UnitHash& hash){
    vote_hash_list_.push_back(hash);
  }
  void set_vote_hash_list(const std::vector<UnitHash>& hash_list){
    vote_hash_list_ = hash_list;
  }
  std::vector<UnitHash> vote_hash_list(){
    return vote_hash_list_;
  }
  void add_vote_list(const VoteUnit& unit){
    vote_list_.push_back(unit);
  }
  void set_vote_list(const std::vector<VoteUnit>& unit_list){
    vote_list_ = unit_list;
  }
  std::vector<VoteUnit> vote_list(){
    return vote_list_;
  }
  uint64_t time_stamp(){
    return time_stamp_;
  }
  void set_time_stamp_with_now(){
    time_stamp_ = time(nullptr);
  }
  void set_time_stamp(uint64_t t){
    time_stamp_ = t;
  }
private:
  //validate unit's hash
  std::vector<UnitHash> check_list_;
  std::vector<UnitHash> vote_hash_list_;
  //0~1000,000
  uint32_t percent_;
  //certificate for vote, but it will delete sometime
  //so,don't contain this value in caculation in sign and hash
  std::vector<VoteUnit> vote_list_;
  uint64_t time_stamp_;
  uint64_t nonce_;
};

class EnterValidateSetUint:public Unit{
public:
  EnterValidateSetUint();
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf, size_t* used_size = nullptr) override;

  UnitHash CalcHash() const;
  virtual void CalcHashAndFill() override;
  virtual bool SignatureAndFill(const PrivateKey& key) override;
  virtual bool Validate(std::string* err) const override;
};

}
}
#endif
