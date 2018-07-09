

#include <iostream>
#include <boost/filesystem.hpp>

#include <store/unit_store.h>
#include <core/key.h>


int main(){

  /*ambr::core::PrivateKey priv_key("0x25e25210dce702d4e36b6c8a17e18dc1d02a9e4f0d1d31c4aee77327cf1641cc");
  std::cout<<"priv_key is:"<<priv_key.encode_to_hex()<<std::endl;
  ambr::core::PublicKey pub_key = ambr::core::GetPublicKeyByPrivateKey(priv_key);
  std::cout<<"pub_key is:"<<pub_key.encode_to_hex()<<std::endl;*/

  //clear db
  system("rm -fr unit.db");

  std::shared_ptr<ambr::store::UnitStore> store = ambr::store::GetUnitStore();
  ambr::core::Amount amount;
  ambr::core::PublicKey pub_key= test_temp::GetPublicKeyByAddress("1234567890123456789012345678901234567890123456789012345678901234");
  if(store->GetBalanceByPubKey(pub_key, amount)){
    std::cout<<"balance open success!"<<std::endl;
    std::cout<<"amount is:"<<amount.data()<<std::endl;
  }else{
    std::cout<<"balance open faild!"<<std::endl;
  }
  std::string err;
  if(!store->SendToAddress(ambr::core::PublicKey("0x1234"), ambr::core::Amount(999), ambr::core::PrivateKey(pub_key), &err)){
    std::cout<<"Send error:"<<err<<std::endl;
  }else{
    std::cout<<"Send Seccess！"<<std::endl;
  }
  if(store->GetBalanceByPubKey(pub_key, amount)){
    std::cout<<"balance open success!"<<std::endl;
    std::cout<<"amount is:"<<amount.data()<<std::endl;
  }else{
    std::cout<<"balance open faild!"<<std::endl;
  }
  return 0;
}
