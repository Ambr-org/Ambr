

#include <iostream>
#include <boost/filesystem.hpp>

#include <store/unit_store.h>
#include <core/key.h>


int main(){
  /*
  priv_key is:25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC
  pub_key is:A51E124CACC600FE50BEE4AC2866BA5F56ADA6792523EAC953460A13716ACBEA
  address is:ambr_179omdinczkoprf4cij8o6dx5bbk9mpoptqndm37e7sxdasz1ijsc8b4yab3
  */
  //clear db
  /*
  {
    ambr::core::PrivateKey prik("0x25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC");
    ambr::core::PublicKey pubk("0xA51E124CACC600FE50BEE4AC2866BA5F56ADA6792523EAC953460A13716ACBEA");
    unsigned char buf[]="123456";
    ambr::core::Signature sign = ambr::core::GetSignByPrivateKey(buf, sizeof(buf), prik);
    std::cout<<ambr::core::SignIsValidate(buf, sizeof(buf), pubk, sign)<<std::endl;
    return 0;
  }
  */
  system("rm -fr unit.db");

  std::shared_ptr<ambr::store::UnitStore> store = ambr::store::GetUnitStore();
  ambr::core::Amount amount;
  ambr::core::PublicKey pub_key= ambr::core::GetPublicKeyByAddress("ambr_179omdinczkoprf4cij8o6dx5bbk9mpoptqndm37e7sxdasz1ijsc8b4yab3");
  if(store->GetBalanceByPubKey(pub_key, amount)){
    std::cout<<"balance open success!"<<std::endl;
    std::cout<<"amount is:"<<amount.data()<<std::endl;
  }else{
    std::cout<<"balance open faild!"<<std::endl;
  }
  std::string err;
  if(!store->SendToAddress(ambr::core::PublicKey("0x1234"), ambr::core::Amount(999), ambr::core::PrivateKey("0x25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC"), &err)){
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
