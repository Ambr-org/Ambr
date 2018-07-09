
#ifndef  AMBR_CORE_UNIT_H_
#define  AMBR_CORE_UNIT_H_
// const function
// const input
// TODO
#include <memory>
#include <utils/uint.h>
#include <core/key.h>
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
  receive = 2
};

class Unit{
  //TODO
  friend class SendUnit;
  friend class ReceiveUnit;
public:
  virtual std::string SerializeJson () const = 0;
  virtual bool DeSerializeJson(const std::string& json) = 0;
  virtual std::vector<uint8_t> SerializeByte() const = 0;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) = 0;

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
//protected
private:
  uint32_t version_;
  UnitType type_;
  PublicKey public_key_;
  UnitHash prev_unit_;
  Amount balance_;
  UnitHash hash_;
  Signature sign_;
  //protected TODO
private:
  Unit();
};

class SendUnit:public Unit{
public:
  SendUnit();
public:
  virtual std::string SerializeJson () const override;
  virtual bool DeSerializeJson(const std::string& json) override;
  virtual std::vector<uint8_t> SerializeByte() const override;
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;

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
  virtual bool DeSerializeByte(const std::vector<uint8_t>& buf) override;

  UnitHash CalcHash() const;
  virtual void CalcHashAndFill() override;
  virtual bool SignatureAndFill(const PrivateKey& key) override;
  virtual bool Validate(std::string* err) const override;
public:
  const PublicKey& from(){
    return from_;
  }
  void set_from(const PublicKey& from){
    from_ = from;
  }
private:
  PublicKey from_;
};

}
}
#endif
