/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_UNIT_STORE_H_
#define AMBR_UNIT_STORE_H_
#include <memory>
#include <core/key.h>
#include <vector>
#include <list>
#include <unordered_map>
namespace ambr{
namespace core{
  class Unit;
  class SendUnit;
  class ReceiveUnit;
  class EnterValidateSetUint;
  class LeaveValidateSetUint;
}
namespace store{

class UnitStore{
public:
  static std::shared_ptr<UnitStore> CreateUnitStoreByBytes(const std::vector<uint8_t>& buf);
public:
  enum StoreType{
    ST_SendUnit = 1,
    ST_ReceiveUnit = 2,
    ST_EnterValidatorSet = 3,
    ST_LeaveValidatorSet = 4
  };
  uint32_t version(){return version_;}
  void set_version(uint32_t version){version_ = version;}
  uint8_t is_validate(){return !validated_hash_.is_zero();}//is validate by validator set
  void set_is_validate(const ambr::core::UnitHash& validate_unit_hash){validated_hash_ = validate_unit_hash;}
  virtual std::string SerializeJson () const = 0;
  virtual bool DeSerializeJson(const std::string& json) = 0;
  virtual std::vector<uint8_t> SerializeByte() const = 0;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) = 0;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() = 0;
public:
  StoreType type(){return type_;}
  void set_type(StoreType type){type = type;}
protected:
  UnitStore(StoreType type):type_(type),version_(0x00000001){}
  StoreType type_;
  uint32_t version_;
  //uint8_t is_validate_;
  ambr::core::UnitHash validated_hash_;//was validated by
};


class SendUnitStore:public UnitStore{
public:
  SendUnitStore(std::shared_ptr<core::SendUnit> unit = nullptr);
public:
  std::shared_ptr<core::SendUnit> unit();
  core::UnitHash receive_unit_hash() const;
  void set_receive_unit_hash(const core::UnitHash hash);

public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() override;
private:
  std::shared_ptr<core::SendUnit> unit_;
  core::UnitHash receive_unit_hash_;

};

class ReceiveUnitStore:public UnitStore{
public:
  ReceiveUnitStore(std::shared_ptr<core::ReceiveUnit> unit = nullptr);
public:
  std::shared_ptr<core::ReceiveUnit> unit();
public:
  virtual std::string SerializeJson() const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() override;
private:
  std::shared_ptr<core::ReceiveUnit> unit_;
};


class EnterValidatorSetUnitStore:public UnitStore{
public:
  EnterValidatorSetUnitStore(std::shared_ptr<core::EnterValidateSetUint> unit = nullptr);
public:
  std::shared_ptr<core::EnterValidateSetUint> unit();
public:
  virtual std::string SerializeJson() const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() override;
private:
  std::shared_ptr<core::EnterValidateSetUint> unit_;
};


class LeaveValidatorSetUnitStore:public UnitStore{
public:
  LeaveValidatorSetUnitStore(std::shared_ptr<core::LeaveValidateSetUint> unit = nullptr);
public:
  std::shared_ptr<core::LeaveValidateSetUint> unit();
public:
  virtual std::string SerializeJson() const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() override;
private:
  std::shared_ptr<core::LeaveValidateSetUint> unit_;
};

class ValidatorItem{
public:// boost const deal byte json
  std::string SerializeJson() const;
  bool DeSerializeJson(const std::string& json);
  bool operator == (const ValidatorItem& it) const;
public:
  core::PublicKey validator_public_key_;
  core::Amount balance_;
  uint64_t enter_nonce_;
  uint64_t leave_nonce_;// this nonce will leave nonce_
};

struct ValidatorSetStore{
public:
  uint32_t version() const;
  void set_version(uint32_t version);
  std::list<ValidatorItem> validator_list() const;
  void set_validator_list(const std::list<ValidatorItem>& item);

  uint64_t current_nonce();
  void set_current_nonce(uint64_t nonce);
  core::PublicKey current_validator();
  void set_current_validator(const core::PublicKey& pub_key);
public:
  void JoinValidator(const ValidatorItem& item);
  void LeaveValidator(const core::PublicKey& pub_key, uint64_t leave_nonce);
  bool GetValidator(const core::PublicKey& pub_key, ValidatorItem& item);
  std::vector<ambr::core::PublicKey> GetValidatorList(uint64_t now_nonce);
  bool IsValidator(const core::PublicKey& pub_key, uint64_t now_nonce);
  bool IsValidator(const core::PublicKey& pub_key);
  void Update(uint64_t now_nonce);
  bool GetNonceTurnValidator(uint64_t nonce, core::PublicKey& pub_key);
public:
  std::string SerializeJson() const;
  bool DeSerializeJson(const std::string& json);
  std::vector<uint8_t> SerializeByte() const;
  bool DeSerializeByte(const std::vector<uint8_t>& buf);
private:

  uint32_t version_;
  uint64_t current_nonce_;
  core::PublicKey current_validator_;
  std::list<ValidatorItem> validator_list_;
};
}//ambr
}//store

#endif
