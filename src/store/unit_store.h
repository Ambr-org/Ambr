/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_UNIT_STORE_H_
#define AMBR_UNIT_STORE_H_
#include <memory>
#include <core/key.h>
namespace ambr{
namespace core{
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
public:
  StoreType type(){return type_;};
  void set_type(StoreType type){type = type;}
protected:
  UnitStore(StoreType type):type_(type){}
private:
  StoreType type_;
};


class SendUnitStore:public UnitStore{
public:
  SendUnitStore(std::shared_ptr<core::SendUnit> unit);
public:
  std::shared_ptr<core::SendUnit> unit();
  core::UnitHash receive_unit_hash() const;
  void set_receive_unit_hash(const core::UnitHash hash);
  uint32_t version();
  void set_version(uint32_t version);
public:
  virtual std::string SerializeJson () const;
  virtual bool DeSerializeJson(const std::string& json);
  virtual std::vector<uint8_t> SerializeByte() const;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf);
private:
  std::shared_ptr<core::SendUnit> unit_;
  uint32_t version_;
  core::UnitHash receive_unit_hash_;
};


class ReceiveUnitStore:public UnitStore{
public:
  ReceiveUnitStore(std::shared_ptr<core::ReceiveUnit> unit);
public:
  std::shared_ptr<core::ReceiveUnit> unit();
  core::UnitHash receive_unit_hash() const;
  void set_receive_unit_hash(const core::UnitHash hash);
  uint32_t version();
  void set_version(uint32_t version);
public:
  virtual std::string SerializeJson () const;
  virtual bool DeSerializeJson(const std::string& json);
  virtual std::vector<uint8_t> SerializeByte() const;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf);
private:
  std::shared_ptr<core::ReceiveUnit> unit_;
  uint32_t version_;
};

}//ambr
}//store

#endif
