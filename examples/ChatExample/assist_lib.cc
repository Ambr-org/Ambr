#include "assist_lib.h"
#include "core/key.h"
#include "core/unit.h"
#include "store/store_manager.h"
char *GetPublicKeyByPrivateKey(const char *private_key)
{
  ambr::core::PrivateKey pri_key;
  pri_key.decode_from_hex(private_key);
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(private_key);
  std::string str = pub_key.encode_to_hex();
  char* rtn = new char[str.length()+1];
  memcpy(rtn, str.data(), str.length());
  rtn[str.length()] = 0;
  return rtn;
}

char *GetSendUnitJson(const char *private_key, const char *to_pub_key, const char *last_hash, unsigned long long balance_now,  unsigned long long amount_in)
{
  ambr::core::PrivateKey pri_key(private_key);
  ambr::core::PublicKey dest_pub(to_pub_key);
  ambr::core::UnitHash last_unit_hash(last_hash);
  ambr::core::Amount amount(balance_now);
  amount-=amount_in;
  ambr::core::SendUnit send_unit;
  send_unit.set_type(ambr::core::UnitType::send);

  send_unit.set_public_key(ambr::core::GetPublicKeyByPrivateKey(pri_key));
  send_unit.set_prev_unit(last_unit_hash);
  send_unit.set_dest(dest_pub);
  send_unit.set_balance(amount);
  amount-=send_unit.SerializeJson().size()*ambr::store::StoreManager::GetTransectionFeeBase();
  send_unit.CalcHashAndFill();
  send_unit.SignatureAndFill(pri_key);
  std::string str = send_unit.SerializeJson();
  char* rtn = new char[str.length()+1];
  memcpy(rtn, str.data(), str.length());
  rtn[str.length()] = 0;
  return rtn;

}

char *GetReceiveUnitJson(const char *private_key, const char *from_hash, unsigned long long from_amount, const char* last_hash, unsigned long long balance_now){
  ambr::core::PrivateKey pri_key(private_key);
  ambr::core::UnitHash from_unit_hash(from_hash);
  ambr::core::UnitHash last_unit_hash(last_hash);
  ambr::core::Amount amount(from_amount);
  amount+=balance_now;
  ambr::core::ReceiveUnit receive_unit;
  receive_unit.set_type(ambr::core::UnitType::receive);

  receive_unit.set_public_key(ambr::core::GetPublicKeyByPrivateKey(pri_key));
  receive_unit.set_prev_unit(last_unit_hash);
  receive_unit.set_from(from_unit_hash);
  receive_unit.set_balance(amount);
  receive_unit.CalcHashAndFill();
  receive_unit.SignatureAndFill(pri_key);
  std::string str = receive_unit.SerializeJson();
  char* rtn = new char[str.length()+1];
  memcpy(rtn, str.data(), str.length());
  rtn[str.length()] = 0;
  return rtn;
}
