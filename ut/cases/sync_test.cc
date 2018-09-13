#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include <glog/logging.h>
#include <boost/signals2.hpp>

#include "store/store_manager.h"
#include "store/unit_store.h"
#include <synchronization/syn_manager.h>
#include <boost/thread.hpp>

class TestCase {
public:
  TestCase()=default;

  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node) {
    std::string tmp = netmsg.hdr.GetCommand();
    std::cout << "temp is" << tmp << std::endl;
    if(NetMsgType::UNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      p_Impl_client -> UnSerialize(buf);
      unit_ = ambr::core::Unit::CreateUnitByByte(buf);
      LOG(INFO) << "Received Unit :" << unit_->SerializeJson();
      version = unit_->version();
      balance = unit_->balance();
    }
    else{
      p_Impl_client->OnReceiveNode(netmsg, p_node);
    }

  }

  void OnAcceptNode(CNode* pnode) {
   pnode->SetReceiveNodeFunc(std::bind(&TestCase::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
  //   p_node->SetDisConnectNodeFunc(std::bind(&ambr::syn::Impl::OnDisConnectNode, this, std::placeholders::_1));
 }

 void OnConnectNode(CNode *pnode){
  p_Impl_client->AddListInNode(pnode);
  pnode->SetReceiveNodeFunc(std::bind(&TestCase::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
}

Ptr_Unit GetUnit(){
  return unit_;
}

void SetImplClient(ambr::syn::Impl* ImplClient){
  p_Impl_client = ImplClient;
}

void SetImplServer(ambr::syn::Impl* ImplServer){
  p_Impl_server = ImplServer;
}

public:
  static uint32_t  version;
  static ambr::core::Amount  balance;

private:
  ambr::syn::Impl* p_Impl_client;
  ambr::syn::Impl* p_Impl_server;

  Ptr_Unit unit_;
};

class SyncTest: public ::testing::Test{
protected:
  void SetUp() override {
    TestCase::version = 0;
    TestCase::balance = 0;
  }

  void TearDown() override {

  }

  static void SetUpTestCase(){
    store_client = std::make_shared<ambr::store::StoreManager>();
    sync_client = std::make_shared<ambr::syn::SynManager>(store_client);

    store_server = std::make_shared<ambr::store::StoreManager>();
    sync_server = std::make_shared<ambr::syn::SynManager>(store_server);

    root_pri_key = "25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC";
    test_prikey1= ambr::core::CreateRandomPrivateKey();
    test_prikey2= ambr::core::CreateRandomPrivateKey();
    store_client->Init("./client");
    store_server->Init("./server");

    tc.SetImplClient(sync_client->GetImpl());
    tc.SetImplServer(sync_server->GetImpl());

    ClientSendUnitConn = store_client->AddCallBackReceiveNewSendUnit(std::bind(&ambr::syn::SynManager::BoardCastNewSendUnit, sync_client.get(), std::placeholders::_1));
    ServerSendUnitConn = store_server->AddCallBackReceiveNewSendUnit(std::bind(&ambr::syn::SynManager::BoardCastNewSendUnit, sync_server.get(), std::placeholders::_1));

    ambr::syn::IPConfig ip ={
        10111, // port
        "127.0.0.1" // ip
      };

      std::vector<ambr::syn::IPConfig> ipconfig;
      ipconfig.push_back(ip);

      ambr::syn::SynManagerConfig sys_config_client{
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

      ambr::syn::SynManagerConfig sys_config_server{
        6,  // max_in_peer
        6, // max_out_peer
        6, //max_in_peer_for_optimize
        6, // max_out_peer_for_optimize
        60, //heart time
        10111, // listen port
        false, // use upnp
        false, // use natp
        false, //use nat pmp
        std::vector<ambr::syn::IPConfig>() // vec_seed
      };

      std::thread th_server(&ambr::syn::SynManager::Init, sync_server.get(), sys_config_server);
      th_server.detach();
      std::this_thread::sleep_for(std::chrono::seconds(2));

      std::thread th_client(&ambr::syn::SynManager::Init, sync_client.get(), sys_config_client);
      th_client.detach();

      std::this_thread::sleep_for(std::chrono::milliseconds(500)); 

      sync_client->GetImpl()-> SetConnectFunc(std::bind(&TestCase::OnConnectNode, tc, std::placeholders::_1));
      sync_client->GetImpl()-> SetAcceptFunc(std::bind(&TestCase::OnAcceptNode, tc, std::placeholders::_1));
    }

    static void TearDownTestCase(){
      system("rm -fr ./client");
      system("rm -fr ./server");
    }

  public:
    static std::shared_ptr<ambr::store::StoreManager> store_client;
    static std::shared_ptr<ambr::store::StoreManager> store_server;

    static std::shared_ptr<ambr::syn::SynManager> sync_client;
    static std::shared_ptr<ambr::syn::SynManager> sync_server;

    static std::string root_pri_key;
    static ambr::core::PrivateKey test_prikey1;
    static ambr::core::PrivateKey test_prikey2;
    static TestCase tc;

    static boost::signals2::connection ClientSendUnitConn;
    static boost::signals2::connection ServerSendUnitConn;
  };

// static data
  std::shared_ptr<ambr::store::StoreManager> SyncTest::store_client;
  std::shared_ptr<ambr::store::StoreManager> SyncTest::store_server;

  std::shared_ptr<ambr::syn::SynManager> SyncTest::sync_client;
  std::shared_ptr<ambr::syn::SynManager> SyncTest::sync_server;

  boost::signals2::connection SyncTest::ClientSendUnitConn;
  boost::signals2::connection SyncTest::ServerSendUnitConn;

  std::string SyncTest::root_pri_key;
  ambr::core::PrivateKey SyncTest::test_prikey1;
  ambr::core::PrivateKey SyncTest::test_prikey2;
  TestCase  SyncTest::tc;

  uint32_t TestCase::version;
  ambr::core::Amount TestCase::balance;

// test case
  TEST_F(SyncTest, SendOneTX){ 
    // waiting p2p module initialize  and get consensus
    std::this_thread::sleep_for(std::chrono::seconds(5));
    bool ret = false;
    ambr::core::PublicKey recv_pub1= ambr::core::GetPublicKeyByPrivateKey(test_prikey1);
    ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(root_pri_key);
    
    ambr::core::UnitHash test_hash;
    std::shared_ptr<ambr::core::Unit> added_unit;
    ambr::core::Amount send_ammout = 1000 * store_client->GetTransectionFeeBase();

    std::string err;
    ambr::core::Amount balance_ori;
    ambr::core::Amount balance_used;
    ambr::core::Amount balance_remainder;

    //make json for the add unit
    std::shared_ptr<ambr::core::SendUnit> unit = std::shared_ptr<ambr::core::SendUnit>(new ambr::core::SendUnit());

     //  send tx
    EXPECT_TRUE(store_client->GetBalanceByPubKey(test_pub, balance_ori));
    bool result = store_client->SendToAddress(recv_pub1, send_ammout, root_pri_key, &test_hash, added_unit, &err);
    EXPECT_TRUE(result) << err ;

    std::this_thread::sleep_for(std::chrono::seconds(5));
    EXPECT_EQ(TestCase::version, added_unit->version());
    store_client->GetBalanceByPubKey(test_pub, balance_remainder);
    EXPECT_EQ(tc.balance, balance_remainder);
  }


  TEST_F(SyncTest, SendTXOnLocalClient)
  {
    // callback func prototype  
    //  void BoardCastNewSendUnit(std::shared_ptr<core::SendUnit> p_unit);
    ClientSendUnitConn.disconnect();

    bool ret = false;
    ambr::core::PublicKey recv_pub1= ambr::core::GetPublicKeyByPrivateKey(test_prikey1);
    ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(root_pri_key);
    
    ambr::core::UnitHash test_hash;
    std::shared_ptr<ambr::core::Unit> added_unit;
    ambr::core::Amount send_ammout = 1000 * store_client->GetTransectionFeeBase();

    std::string err;
    ambr::core::Amount balance_ori;
    ambr::core::Amount balance_used;
    ambr::core::Amount balance_remainder;

    //make json for the add unit
    std::shared_ptr<ambr::core::SendUnit> unit = std::shared_ptr<ambr::core::SendUnit>(new ambr::core::SendUnit());

     //  send tx
    EXPECT_TRUE(store_client->GetBalanceByPubKey(test_pub, balance_ori));
    bool result = store_client->SendToAddress(recv_pub1, send_ammout, root_pri_key, &test_hash, added_unit, &err);
    EXPECT_TRUE(result) << err ;

    std::this_thread::sleep_for(std::chrono::seconds(5));
    store_client->GetBalanceByPubKey(test_pub, balance_remainder);
    EXPECT_EQ(balance_ori - send_ammout, balance_remainder);
  }


  TEST_F(SyncTest, SendTxOnLocalServer)
  {
    // callback func prototype  
    //  void BoardCastNewSendUnit(std::shared_ptr<core::SendUnit> p_unit);
    ServerSendUnitConn.disconnect();

    bool ret = false;
    ambr::core::PublicKey recv_pub2= ambr::core::GetPublicKeyByPrivateKey(test_prikey2);
    ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(root_pri_key);
    
    ambr::core::UnitHash test_hash;
    std::shared_ptr<ambr::core::Unit> added_unit;
    ambr::core::Amount send_ammout = 1000 * store_server->GetTransectionFeeBase();

    std::string err;
    ambr::core::Amount balance_ori;
    ambr::core::Amount balance_used;
    ambr::core::Amount balance_remainder;

    //make json for the add unit
    std::shared_ptr<ambr::core::SendUnit> unit = std::shared_ptr<ambr::core::SendUnit>(new ambr::core::SendUnit());

     //  send tx
    EXPECT_TRUE(store_server->GetBalanceByPubKey(test_pub, balance_ori));
    bool result = store_server->SendToAddress(recv_pub2, send_ammout, root_pri_key, &test_hash, added_unit, &err);
    EXPECT_TRUE(result) << err ;

    std::this_thread::sleep_for(std::chrono::seconds(5));
    store_server->GetBalanceByPubKey(test_pub, balance_remainder);
    EXPECT_EQ(balance_ori - send_ammout, balance_remainder);
  }


  TEST_F(SyncTest, SendTxOnNet)
  {
    // callback func prototype  
    //  void BoardCastNewSendUnit(std::shared_ptr<core::SendUnit> p_unit);
    store_client->AddCallBackReceiveNewSendUnit(std::bind(&ambr::syn::SynManager::BoardCastNewSendUnit, sync_client.get(), std::placeholders::_1));
    store_server->AddCallBackReceiveNewSendUnit(std::bind(&ambr::syn::SynManager::BoardCastNewSendUnit, sync_server.get(), std::placeholders::_1));

    bool ret = false;
    ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(root_pri_key);
    
    ambr::core::UnitHash test_hash;
    std::shared_ptr<ambr::core::Unit> added_unit;
    ambr::core::Amount send_ammout = 1000 * store_client->GetTransectionFeeBase();

    std::string err;
    ambr::core::Amount balance_ori;
    ambr::core::Amount balance_used;
    ambr::core::Amount balance_remainder;

    //make json for the add unit
    std::shared_ptr<ambr::core::SendUnit> unit = std::shared_ptr<ambr::core::SendUnit>(new ambr::core::SendUnit());

     //  send tx
    EXPECT_TRUE(store_client->GetBalanceByPubKey(test_pub, balance_ori));
    bool result = store_client->SendToAddress(test_pub, send_ammout, root_pri_key, &test_hash, added_unit, &err);
    EXPECT_TRUE(result) << err ;

    std::this_thread::sleep_for(std::chrono::seconds(5));
    EXPECT_NE(TestCase::version, added_unit->version());
    store_client->GetBalanceByPubKey(test_pub, balance_remainder);
    EXPECT_NE(tc.balance, balance_remainder);
  }