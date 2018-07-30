

#include <iostream>
#include <boost/filesystem.hpp>

#include <store/store_manager.h>
#include <core/key.h>
#include <QApplication>
#include <glog/logging.h>
#include "store_example_main_widget.h"
#include "net_test.h"
/*
F49E1B9F671D0B244744E07289EA0807FAE09F8335F0C1B0629F1BF924CA64E1
6C300AF488B768B4F4E8DB76E695D4662FDA864445B64931597A943B811BB978
ambr_msdu9e53rdgqj1g9nnykor6bpfja65cuhjsaxctwpupjgtmpaufjatd3i3u1
=================
29176270484F74852C5ABCBFEF26C4193FE4C2E4C522984D833329EDD502DC84
774134B6CD0DD86C134977EE464206FE8B59EA627E00ACEC4396A0394E6CC084
ambr_m9djoeib66is89791o796pmo1iz68o9ddnzf13sagzxknbifrg5teuk83tx1
=================
9812383BF3CE164A3D968186BEBA1CCFF299C9C59448A19BF3C0582336E01301
2778CAB332ECA9A4F59C70F850833B578A44B2D7CEED9A1AC3286D6A44616C9F
ambr_p8yp7tx7z6u484bff5c8efamfqmhfskacwopm34cr9wrstmnb7u7mscsrub1
=================
C56E273AE386A16846D5710F2B04DE75DE5D4DD086D15ABBFF0B184BC01F81C5
CBE8E1251AE6332D9C7DEECE606D297505289DFCE9AE60AF619FAADF7249CB14
ambr_sou3mbnonrkm6sxucx95pq4egftszg477axkkp3egpuu9gp7mjsojk6wazk3
=================
C99FC6C3EF33BAB82A8DC27C3D6C26D90DFF3FBE1EB7BA6996A88662A34E031E
8F062E04C188E7636B92F19E1ABD9033A4BC138DC0D68E1BFD91A8E9F58FAF38
ambr_7jmrpt67rsdzrt9xaf6uzfrjp8iurbiq6xe1syc5yew7sofe9945e4r78r53
=================
158DA7D0ED279C29C0F60599E7009F000E4878C26D12E8031DFA7E93C13C0E88
DB5AA95D2D110C6CD7CE12B2C11C6020C839FC011BF94BF5DA97D2FD762DBA4E
ambr_63tyromogkgu4uozky7oxthbsz841y99a8a18g6rko6wwdmfea6tkg7ottp3
=================
1131372AAE12C73F25388E525B8664096A1FF1C79474E562A82537F80F91A337
A39244660A8648520B89E6ED390D739D98839756AACF6E34B3696B90D00EA51B
ambr_3zj11iy9uabx1a5kddt8dtrfhpcfodgire99q869fqsmr7acak3o1mjakwa3
=================
19BA73EC64C3C296E1971EE5B668C591F5F206DBE5DCAA3FBAF22610767C6558
9DA127548F187E0BC26C80BD1DE1D6E7858D23065D2B0D92E20571D617F583C5
ambr_w4thst8b7y1dzdrtjd36gbp3dbqeijnj7wsfxiq5x71s83h3y58yacx63f93
=================
C38359CD5BD9C5FC65482FFE0E016B2E5E046F7A99E0EFDBCCDF23D2D12C7A3E
EC992B952B4B115B2E02CC5B952F85368231F32570E9A31D1023318C43D8472B
ambr_bzcx1qg1dsjix3jjjsa1jgenb9wcks984nfcrqnku4m71qedjrkpkcg7s6u3
=================
6EDB77B51291C19D82B1105A507008D10B5A0C5CCB5459129D64A3AD8D8AEEFC
12D5583F54F34F6F74922ED9EE678E67CCF2FB4FEAA8C4AB6325D725578BC9A9
ambr_mbhwq8g7bfkqrdo6qgb8pokraotznxdyeyswrmsxspd6btxfhtwboz1dop61
*/
ambr::core::PrivateKey pri_key[10]={"F49E1B9F671D0B244744E07289EA0807FAE09F8335F0C1B0629F1BF924CA64E1",
                                    "29176270484F74852C5ABCBFEF26C4193FE4C2E4C522984D833329EDD502DC84",
                                    "9812383BF3CE164A3D968186BEBA1CCFF299C9C59448A19BF3C0582336E01301",
                                    "C56E273AE386A16846D5710F2B04DE75DE5D4DD086D15ABBFF0B184BC01F81C5",
                                    "C99FC6C3EF33BAB82A8DC27C3D6C26D90DFF3FBE1EB7BA6996A88662A34E031E",
                                    "158DA7D0ED279C29C0F60599E7009F000E4878C26D12E8031DFA7E93C13C0E88",
                                    "1131372AAE12C73F25388E525B8664096A1FF1C79474E562A82537F80F91A337",
                                    "19BA73EC64C3C296E1971EE5B668C591F5F206DBE5DCAA3FBAF22610767C6558",
                                    "C38359CD5BD9C5FC65482FFE0E016B2E5E046F7A99E0EFDBCCDF23D2D12C7A3E",
                                    "6EDB77B51291C19D82B1105A507008D10B5A0C5CCB5459129D64A3AD8D8AEEFC"};
ambr::core::PrivateKey GetPriKey(int i){return pri_key[i];}
ambr::core::PublicKey GetPubKey(int i){return ambr::core::GetPublicKeyByPrivateKey(pri_key[i]);}
std::string GetAddr(int i){return ambr::core::GetAddressStringByPublicKey(GetPubKey(i));}

int main(int argc, char**argv){
  //init log
  FLAGS_log_dir = ".";
  FLAGS_colorlogtostderr = true;
  google::InitGoogleLogging("Ambr");
  google::SetStderrLogging(google::GLOG_INFO);
  //reset db
  /*ambr::core::PrivateKey pri_key_admin("0x25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC");
  std::string addr_admin("ambr_y4bwxzwwrze3mt4i99n614njtsda6s658uqtue9ytjp7i5npg6pz47qdjhx3");
  system("rm -fr unit.db");
  LOG(INFO)<<"Clear DB";
  std::shared_ptr<ambr::store::StoreManager> store_manager = ambr::store::GetStoreManager();
  ambr::core::PublicKey pub_key= ambr::core::GetPublicKeyByAddress(addr_admin);
  ambr::core::Amount amount;

  //===================================
  std::cout<<"=====>1.Get balance of creator user."<<std::endl;
  if(store_manager->GetBalanceByPubKey(pub_key, amount)){
    std::cout<<"balance open success!"<<std::endl;
    std::cout<<"amount is:"<<amount.data()<<std::endl;
  }else{
    std::cout<<"balance open faild!"<<std::endl;
  }

  //===================================
  std::cout<<"=====>2.Send token to all 10 users, and 1~10 times"<<std::endl;
  for(size_t i = 0; i < sizeof(pri_key)/sizeof(pri_key[0]); i++){
    std::cout<<"****************************"<<i<<std::endl;
    //for(size_t times = 0; times < i+1; times++){
    std::string err;
    if(!store_manager->SendToAddress(GetPubKey(i), ambr::core::Amount(10000), ambr::core::PrivateKey(pri_key_admin), nullptr, &err)){
      std::cout<<"Send error:"<<err<<std::endl;
    //  }
    }
  }
  //===================================
  std::cout<<"=====>4.Show All wait for recieve unit"<<std::endl;
  for(int i = 0; i < 10; i++){
    std::cout<<"public key"<<GetPubKey(i).encode_to_hex()<<std::endl;
    std::list<ambr::core::UnitHash> hash_list = store_manager->GetWaitForReceiveList(GetPubKey(i));
    for(auto iter = hash_list.begin(); iter != hash_list.end(); iter++){
      std::cout<<iter->encode_to_hex()<<std::endl;
    }
  }
  //===================================
  std::cout<<"=====>2.1 receive token test"<<std::endl;
  {
    std::string err;
    if(!store_manager->ReceiveFromUnitHash(ambr::core::UnitHash("0xFEFDF1969546F5C85FBB9F335D4A30C818D889A4FC577197E11281C8720898BF"),
                                          GetPriKey(1), nullptr, &err)){
      std::cout<<"Send error:"<<err<<std::endl;
    }
  }
  //===================================
  std::cout<<"=====>3.Show All user balacne"<<std::endl;
  if(store_manager->GetBalanceByPubKey(pub_key, amount)){
    std::cout<<"Creator User banalce is:"<<amount.data()<<std::endl;
  }else{
    std::cout<<"Creator balance open faild!"<<std::endl;
  }
  for(int i = 0; i < 10; i++){
    if(store_manager->GetBalanceByPubKey(GetPubKey(i), amount)){
      std::cout<<"User "<<i<<"'s banalce is:"<<amount.data()<<std::endl;
    }else{
      std::cout<<"Get balance open faild!"<<"User"<<i<<std::endl;
    }
  }
  ambr::net::NetManager net_manager;
  ambr::net::NetManagerConfig config;
  config.max_in_peer_ = 8;
  config.max_out_peer_ = 8;
  config.max_in_peer_for_optimize_ = 8;
  config.max_out_peer_for_optimize_ = 8;
  config.listen_port_ = 9991;
  config.seed_list_.push_back(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::from_string("10.39.0.34"), 9995));
  config.use_upnp_ = false;
  config.use_nat_pmp_ = false;
  config.use_natp_ = false;
  config.heart_time_ = 88;//second of heart interval
  net_manager.init(config);*/
  QApplication app(argc, argv);
  StoreExampleMainWidget widget;
  widget.show();
  app.exec();
  return 0;
}
