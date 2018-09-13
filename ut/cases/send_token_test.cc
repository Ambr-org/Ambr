#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include <glog/logging.h>

#include "store/store_manager.h"
#include "store/unit_store.h"
#include <synchronization/syn_manager.h>
#include <boost/thread.hpp>

class TestCase {
public:
  TestCase()=default;

  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node) {
    std::string tmp = netmsg.hdr.GetCommand();
    
    if(NetMsgType::UNIT == tmp){
     std::vector<uint8_t> buf;
     buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

     p_Impl -> UnSerialize(buf);
     unit_ = ambr::core::Unit::CreateUnitByByte(buf);
     version = unit_->version();
     balance = unit_->balance();
   }
   else{
    p_Impl->OnReceiveNode(netmsg, p_node);
  }

}

void OnAcceptNode(CNode* pnode) {
 pnode->SetReceiveNodeFunc(std::bind(&TestCase::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
  //   p_node->SetDisConnectNodeFunc(std::bind(&ambr::syn::Impl::OnDisConnectNode, this, std::placeholders::_1));
}

void OnConnectNode(CNode *pnode){
  p_Impl->AddListInNode(pnode);
  pnode->SetReceiveNodeFunc(std::bind(&TestCase::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
}

Ptr_Unit GetUnit(){
  return unit_;
}

void SetImpl(ambr::syn::Impl* Impl){
  p_Impl = Impl;
}

public:
  static uint32_t  version;
  static ambr::core::Amount  balance;

private:
  ambr::syn::Impl* p_Impl;
  Ptr_Unit unit_;
};


class SendTest: public ::testing::Test{
protected:
  void SetUp() override {

  }

  void TearDown() override {

  }

  static void SetUpTestCase(){
    store_manager = std::make_shared<ambr::store::StoreManager>();
    syn_manager = std::make_shared<ambr::syn::SynManager>(store_manager);
    root_pri_key = "25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC";
    store_manager->Init("./db");
    tc.SetImpl(syn_manager->GetImpl());

    store_manager->AddCallBackReceiveNewSendUnit(std::bind(&ambr::syn::SynManager::BoardCastNewSendUnit, syn_manager.get(), std::placeholders::_1));
    store_manager->AddCallBackReceiveNewReceiveUnit(std::bind(&ambr::syn::SynManager::BoardCastNewReceiveUnit, syn_manager.get(), std::placeholders::_1));
    store_manager->AddCallBackReceiveNewValidatorUnit(std::bind(&ambr::syn::SynManager::BoardCastNewValidatorUnit, syn_manager.get(), std::placeholders::_1));
    store_manager->AddCallBackReceiveNewJoinValidatorSetUnit(std::bind(&ambr::syn::SynManager::BoardCastNewJoinValidatorSetUnit, syn_manager.get(), std::placeholders::_1));
    store_manager->AddCallBackReceiveNewLeaveValidatorSetUnit(std::bind(&ambr::syn::SynManager::BoardCastNewLeaveValidatorSetUnit, syn_manager.get(), std::placeholders::_1));

    ambr::syn::IPConfig ip ={
        10111, // port
        "127.0.0.1" // ip
      };

      std::vector<ambr::syn::IPConfig> ipconfig;
      ipconfig.push_back(ip);

      ambr::syn::SynManagerConfig sys_config{
        6,  // max_in_peer
        6, // max_out_peer
        6, //max_in_peer_for_optimize
        6, // max_out_peer_for_optimize
        60, //heart time
        8091, // listen port
        false, // use upnp
        false, // use natp
        false, //use nat pmp
        ipconfig // vec_seed
      };

      std::thread tThread(&ambr::syn::SynManager::Init, syn_manager.get(), sys_config);
      tThread.detach();
      std::this_thread::sleep_for(std::chrono::milliseconds(500)); 

      syn_manager->GetImpl()-> SetConnectFunc(std::bind(&TestCase::OnConnectNode, tc, std::placeholders::_1));
      syn_manager->GetImpl()-> SetAcceptFunc(std::bind(&TestCase::OnAcceptNode, tc, std::placeholders::_1));
    }

    static void TearDownTestCase(){
      system("rm -fr ./db");
    }

  public:
    static std::shared_ptr<ambr::store::StoreManager> store_manager;
    static std::shared_ptr<ambr::syn::SynManager> syn_manager;
    static ambr::core::PrivateKey test_pri;
    static std::string root_pri_key;
    static TestCase tc;
  };

  std::shared_ptr<ambr::store::StoreManager> SendTest::store_manager;
  std::shared_ptr<ambr::syn::SynManager> SendTest::syn_manager;
  ambr::core::PrivateKey SendTest::test_pri;
  std::string SendTest::root_pri_key;
  TestCase  SendTest::tc;

  uint32_t TestCase::version;
  ambr::core::Amount TestCase::balance;



  TEST_F(SendTest, SendOneTX){ 
    // waiting p2p module initialize  and get consensus
    std::this_thread::sleep_for(std::chrono::seconds(3));
    bool ret = false;
    ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(root_pri_key);
    
    ambr::core::UnitHash test_hash;
    std::shared_ptr<ambr::core::Unit> added_unit;
    ambr::core::Amount send_ammout = 1000*store_manager->GetTransectionFeeBase();

    std::string err;
    ambr::core::Amount balance_ori;
    ambr::core::Amount balance_used;
    ambr::core::Amount balance_remainder;

  //===last_unit_hash===========================
  //test send 1----->SendToAddress

    //make json for the add unit
    std::shared_ptr<ambr::core::SendUnit> unit = std::shared_ptr<ambr::core::SendUnit>(new ambr::core::SendUnit());

     //  send tx
    EXPECT_TRUE(store_manager->GetBalanceByPubKey(test_pub, balance_ori));
    bool result = store_manager->SendToAddress(test_pub, send_ammout, root_pri_key, &test_hash, added_unit, &err);
    EXPECT_TRUE(result) << err ;

    std::this_thread::sleep_for(std::chrono::seconds(4));
    EXPECT_EQ(TestCase::version, added_unit->version());
    store_manager->GetBalanceByPubKey(test_pub, balance_remainder);
    EXPECT_EQ(tc.balance, balance_remainder);
  }

  TEST_F(SendTest, SendMoreTX){ 
    bool ret = false;
    auto sendtimes =5;
    ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(root_pri_key);
    
    ambr::core::UnitHash test_hash;
    std::shared_ptr<ambr::core::Unit> added_unit;
    ambr::core::Amount send_ammout = 1000*store_manager->GetTransectionFeeBase();

    std::string err;
    ambr::core::Amount balance_ori;
    ambr::core::Amount balance_used;
    ambr::core::Amount balance_remainder;

  //===last_unit_hash===========================
  //test send 1----->SendToAddress
    EXPECT_TRUE(store_manager->GetBalanceByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), balance_ori));
    for(int i = 0; i < sendtimes; i++){
      bool result = store_manager->SendToAddress(test_pub, send_ammout, root_pri_key, &test_hash, added_unit, &err);
      EXPECT_TRUE(result) << err ;
    }

    std::this_thread::sleep_for(std::chrono::seconds(4));

    EXPECT_EQ(TestCase::version, added_unit->version());
    store_manager->GetBalanceByPubKey(test_pub, balance_remainder);
    EXPECT_EQ(tc.balance,  balance_remainder);     
  }