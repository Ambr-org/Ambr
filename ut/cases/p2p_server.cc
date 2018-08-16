#include <iostream>
#include <gtest/gtest.h>
#include <glog/logging.h>
#include <p2p/net.h>
#include <p2p/init.h>
#include <p2p/netbase.h>
#include <p2p/net_processing.h>
#include <p2p/scheduler.h>
#include <p2p/chainparams.h>
#include <p2p/version.h>
#include <p2p/netmessagemaker.h>
#include <p2p/utiltime.h>

class P2PTest: public ::testing::Test{
protected:
  void SetUp() override {
    options.nListenPort = 18090;
    CScheduler scheduler;
    try {
      SelectParams(gArgs.GetChainName(), options.nListenPort);
    } catch (const std::exception& e) {
      fprintf(stderr, "Error: %s\n", e.what());
      exit(1);
    }
    connman = std::unique_ptr<CConnman>(new CConnman(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())));
    ASSERT_TRUE(connman);
    peerLogic = std::unique_ptr<PeerLogicValidation>(new  PeerLogicValidation(connman.get(), scheduler, false));
    ASSERT_TRUE(peerLogic);
  }

  void TearDown() override {
   
  }

  static void SetUpTestCase(){
   pnode = nullptr;
   
 }

 static void TearDownTestCase(){
  delete pnode;
  pnode = nullptr;
  ambr::p2p::Interrupt();
  ambr::p2p::Shutdown(); 
}

public:
  static std::unique_ptr<CConnman> connman;
  static std::unique_ptr<PeerLogicValidation> peerLogic;
  static CNode* pnode  ;
  static  int sockfd;
  static CConnman::Options options;
};

int P2PTest::sockfd  = 0;
CNode* P2PTest::pnode = nullptr;
std::unique_ptr<CConnman>  P2PTest::connman;
std::unique_ptr<PeerLogicValidation> P2PTest::peerLogic;
CConnman::Options  P2PTest::options;

TEST_F(P2PTest, StartSever){ 
  auto start_server = [&](CConnman::Options &&  options ){
    bool ret = ambr::p2p::init(std::move(options));
    ASSERT_TRUE(ret);
    ambr::p2p::WaitForShutdown();
  };
  auto options =  P2PTest::options;
  std::thread t1(start_server, std::move(options));
  t1.detach();
}


TEST_F (P2PTest, ConnectToServer){
 char buff[1024];
 struct sockaddr_in cli_addr;
 std::this_thread::sleep_for(std::chrono::seconds(1));
 memset(&cli_addr, 0, sizeof(cli_addr));
 P2PTest::sockfd = socket(AF_INET, SOCK_STREAM , 0);
 ASSERT_NE(sockfd, SOCKET_ERROR) << "create socket failed" ;

 auto s =inet_pton(AF_INET, "127.0.0.1", &cli_addr.sin_addr);
 ASSERT_EQ(s, 1) << "inet_pton failed";
 cli_addr.sin_port = htons(options.nListenPort);
 cli_addr.sin_family = AF_INET;

 CAddress addr_connect(CService(cli_addr.sin_addr, options.nListenPort), NODE_NONE);
 bool connected = ConnectSocketDirectly(addr_connect, sockfd, 3000, false);
 ASSERT_TRUE(connected);

 pnode = new CNode(0, NODE_NONE, 0, sockfd, addr_connect, 0, 0, addr_connect,  "", false);
 ASSERT_NE(pnode, nullptr) ;
}

TEST_F(P2PTest, GetConsensus){
  int max_len = 0x1000;
  char buff[max_len] = {0};
  ASSERT_TRUE(pnode);
  ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
  uint64_t nonce = pnode->GetLocalNonce();
  int nNodeStartingHeight = pnode->GetMyStartingHeight();
  NodeId nodeid = pnode->GetId();
  CAddress addr = pnode->addr;

  CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
  CAddress addrMe = CAddress(CService(), nLocalNodeServices);

  connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, GetTime(), addrYou, addrMe,
    nonce, strSubVersion, nNodeStartingHeight, ::fRelayTxes));

  struct timeval timeout;
  timeout.tv_sec  = 3;
  timeout.tv_usec = 0;
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(P2PTest::sockfd, &fdset);
  int nRet = select(P2PTest::sockfd + 1, &fdset, nullptr,  nullptr, &timeout);
  ASSERT_GT(nRet, 0) << "connection error";

  int nBytes = read(sockfd, buff, max_len);

  if(nBytes == 0){
    std::cout << "peer close  the socket"  << std::endl;
  }
  ASSERT_GT(nBytes, 0) << "read error" ;

  bool notify = false;
  auto ret = pnode->ReceiveMsgBytes(buff, nBytes, notify);
  if (! ret){
    pnode->CloseSocketDisconnect();
  }

  ASSERT_TRUE(ret)  << " process message failed. " ;

  auto RecvMsg = pnode->GetRecvMsg().front();
  int version = 0;
  RecvMsg. vRecv >> version;
  ASSERT_EQ(version, PROTOCOL_VERSION);
}


TEST_F(P2PTest, SerializeMessageToInt){
  std::string strCommand = "reject";
  int nonce = 39892389;
  CSerializedNetMsg msg = CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, nonce);

   std::string str(msg.data.begin() + 7, msg.data.begin() + msg.data.size());
   std::stringstream stream(str);
   int  len = 0;  
   Unserialize(stream, len);
   ASSERT_EQ(len, nonce);
}

TEST_F(P2PTest, SerializeMessageToString){
  std::string strCommand = "reject";
  std::string data = "socket error";
  CSerializedNetMsg msg = CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, data);

   std::string str(msg.data.begin() + 7, msg.data.begin() + msg.data.size());
   std::stringstream stream(str);
   decltype(data) error_msg; 
   Unserialize(stream, error_msg);
   ASSERT_EQ(data, error_msg);

}