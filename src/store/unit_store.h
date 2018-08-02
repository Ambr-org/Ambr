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
namespace ambr{
namespace core{
  class Unit;
  class SendUnit;
  class ReceiveUnit;
}
namespace store{

class UnitStore{
public:
  static std::shared_ptr<UnitStore> CreateUnitStoreByBytes(const std::vector<uint8_t>& buf);
public:
  enum StoreType{
    ST_SendUnit = 1,
    ST_ReceiveUnit = 2
  };
  virtual std::string SerializeJson () const = 0;
  virtual bool DeSerializeJson(const std::string& json) = 0;
  virtual std::vector<uint8_t> SerializeByte() const = 0;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) = 0;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() = 0;
public:
  StoreType type(){return type_;}
  void set_type(StoreType type){type = type;}
protected:
  UnitStore(StoreType type):type_(type){}
private:
  StoreType type_;
};


class SendUnitStore:public UnitStore{
public:
  SendUnitStore(std::shared_ptr<core::SendUnit> unit = nullptr);
public:
  std::shared_ptr<core::SendUnit> unit();
  core::UnitHash receive_unit_hash() const;
  void set_receive_unit_hash(const core::UnitHash hash);
  uint32_t version();
  void set_version(uint32_t version);
  uint8_t is_validate();//is validate by validator set
  void set_is_validate(uint8_t validate);
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() override;
private:
  std::shared_ptr<core::SendUnit> unit_;
  uint32_t version_;
  core::UnitHash receive_unit_hash_;
  uint8_t is_validate_;
};


class ReceiveUnitStore:public UnitStore{
public:
  ReceiveUnitStore(std::shared_ptr<core::ReceiveUnit> unit = nullptr);
public:
  std::shared_ptr<core::ReceiveUnit> unit();
  uint32_t version();
  void set_version(uint32_t version);
  uint8_t is_validate();//is validate by validator set
  void set_is_validate(uint8_t validate);
public:
  virtual std::string SerializeJson() const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;
  virtual std::shared_ptr<ambr::core::Unit> GetUnit() override;
private:
  std::shared_ptr<core::ReceiveUnit> unit_;
  uint32_t version_;
  uint8_t is_validate_;
};

}//ambr
}//store

#endif
