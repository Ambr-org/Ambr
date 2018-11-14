#include "p2p/net.h"
#include <p2p/init.h>
#include "netbase.h"
#include "shutdown.h"
#include "scheduler.h"
#include "syn_manager.h"
#include "chainparams.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "store/unit_store.h"

#include <list>
#include <sstream>
#include <functional>
#include <boost/bind.hpp>
#include <glog/logging.h>
#include <boost/thread.hpp>
#include <boost/threadpool.hpp>
#include <store/store_manager.h>
#include "syn_manager.h"
#define FIXED_RATE 70
#define MAX_CONNECTIONS 12
/*class SynState{
public:
  void OnTimeOut(const boost::system::error_code& ec){
    if(!ec){
      //超时
    }
  }
  boost::asio::deadline_timer timer_;
  bool is_sync_ = false;
  bool is_online_ = false;
  boost::function<void()> on_time_out_cb_;
  SynState(boost::asio::io_service &ios):timer_(boost::posix_time::millisec(15000)){

  }
};*/

class ambr::syn::SynManager::Impl{
public:
  Impl(Ptr_StoreManager p_store_manager);
  uint32_t GetNodeCount();
  void AddListInNode(CNode *pnode);
  bool GetIfPauseSend(const std::string &addr);
  bool GetIfPauseReceive(const std::string &addr);
  void RemoveNode(CNode* p_node, uint32_t second);
  bool UnSerialize(std::vector<uint8_t>& vec_bytes);
  bool Init(const ambr::syn::SynManagerConfig& config);
  void SendMessage(CSerializedNetMsg&& msg, CNode* p_node);
  void SetOnAccept(const std::function<void(CNode*)>& func);
  void SetOnConnected(const std::function<void(CNode*)>& func);
  void SetOnDisconnect(const std::function<void(CNode*)>& func);
  void BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node);
  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node);

  void ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node);
  void ReturnUnit(const std::vector<uint8_t>& buf, CNode* p_node);

private:
  void Shutdown();
  void WaitForShutdown();
  void IoServiceThread();
  void IosDenastySyn(const boost::system::error_code& ec);
public:
  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisConnectNode(CNode* p_node);

private:
  bool exit_;
  uint64_t num_dyn_no_;
  uint64_t num_node_no_;
  CNode* p_max_no_node_;
  uint32_t reqdynastyno_;
  std::mutex state_mutex_;
  Ptr_CConnman p_cconnman_;
  Ptr_CScheduler p_scheduler;
  //ambr::syn::SynState state_;
  Ptr_StoreManager p_storemanager_;
  std::mutex nodes_mutex_;
  std::list<CNode*> list_in_nodes_;
  std::list<CNode*> list_out_nodes_;
  std::list<Ptr_Unit> list_ptr_unit_;
  ambr::syn::SynManagerConfig config_;
  ambr::core::UnitHash validator_hash_;
  Ptr_PeerLogicValidation p_peerLogicValidation_;



  std::function<void(CNode*)> on_accept_node_func_;
  std::function<void(CNode*)> on_connect_node_func_;
  std::function<void(CNode*)> on_disconnect_node_func_;
private:
  boost::asio::io_service ios_;
  std::thread ios_thread;
  bool is_sync_;
  bool is_online_;
  boost::asio::deadline_timer dynasty_timer_;
  uint32_t dynasty_timer_value_;
  boost::asio::deadline_timer sync_timer_;
  uint32_t sync_timer_value_;
  CNode* node_sync_;
  void StartSyn(CNode* node_sync){
    static std::mutex mutex;
    std::lock_guard<std::mutex> lk(mutex);
    if(is_sync_ == true)return;
    is_sync_ = true;
    node_sync_ = node_sync;
    //request sync
    SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, p_storemanager_->GetLastValidatedUnitHash().encode_to_hex()), node_sync);
    LOG(WARNING)<<">>>>>>>>>>start sync";
    sync_timer_.expires_from_now(boost::posix_time::milliseconds(sync_timer_value_));
    sync_timer_.async_wait(boost::bind(&ambr::syn::SynManager::Impl::OnSyncTimeOut, this, boost::asio::placeholders::error));
  }
  void OnGetSync(){
    LOG(INFO)<<"Get sync data";
    sync_timer_.cancel();
    is_sync_ = false;
  }
  void OnSyncTimeOut(const boost::system::error_code& ec){
    LOG(WARNING)<<ec.message();
    if(ec)return;
    LOG(WARNING)<<"<<<<<<<<<<<<sync timeout";
    //sync_timer_.expires_from_now(boost::posix_time::milliseconds(sync_timer_value_));
    //sync_timer_.async_wait(boost::bind(&ambr::syn::SynManager::Impl::OnSyncTimeOut, this, _1));
    is_sync_ = false;
  }
};

//All of the scenarios
//1. Send unit delayed.
//2. Request unit failed.
//3. Wrong unit sequence
//4. randmise peers, dynasty,
//5. node, island,
//6. 硬分叉处理， ？？
//7. 消息太多cpu能力不足， 1. 加大内存， 2. 丢掉重传
//8. 带宽太窄， 发布出去， 直接丢掉

ambr::syn::SynManager::Impl::Impl(Ptr_StoreManager p_store_manager)
  : exit_(false)
  , num_dyn_no_(0)
  , num_node_no_(0)
  , p_max_no_node_(nullptr)
  , reqdynastyno_(0)
  , p_cconnman_(std::make_shared<CConnman>(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())))
  , p_scheduler(std::make_shared<CScheduler>())
  , p_storemanager_(p_store_manager)
  , is_sync_(false)
  , is_online_(false)
  , dynasty_timer_(ios_)
  , dynasty_timer_value_(1000)
  , sync_timer_(ios_)
  , sync_timer_value_(1000)
  , node_sync_(nullptr){
}

uint32_t ambr::syn::SynManager::Impl::GetNodeCount(){
  std::lock_guard<std::mutex> lk(nodes_mutex_);
  return list_in_nodes_.size() + list_out_nodes_.size();
}

void ambr::syn::SynManager::Impl::AddListInNode(CNode *pnode){
  std::lock_guard<std::mutex> lk(nodes_mutex_);
  list_in_nodes_.push_back(pnode);
}

bool ambr::syn::SynManager::Impl::GetIfPauseSend(const std::string &addr){
  return p_cconnman_->GetIfPauseSend(addr);
}

bool ambr::syn::SynManager::Impl::GetIfPauseReceive(const std::string &addr){
  return p_cconnman_->GetIfPauseReceive(addr);
}

void ambr::syn::SynManager::Impl::RemoveNode(CNode* p_node, uint32_t second){
  /*list_in_nodes_.remove(p_node);
  list_out_nodes_.remove(p_node);*/
  p_node->fDisconnect = true;
}

bool ambr::syn::SynManager::Impl::UnSerialize(std::vector<uint8_t>& vec_bytes){
  size_t data_length = vec_bytes.size();size_t i = std::numeric_limits<unsigned int>::max();
  if(0 >= data_length){
    return false;
  }
  else if(253 >= data_length){
    uint8_t msg_size = vec_bytes[0];
    if(data_length - 1 == msg_size){
      auto it = vec_bytes.begin();
      vec_bytes.erase(it);
    }
    else{
      return false;
    }
  }
  else if(std::numeric_limits<unsigned short>::max() + 3 >= data_length){
    uint16_t msg_size = vec_bytes[2] * 256 + vec_bytes[1];
    if(data_length - 3 == msg_size){
      auto it = vec_bytes.begin();
      vec_bytes.erase(it, it + 3);
    }
    else{
      return false;
    }
  }
  else if(i + 5 >= data_length){
    uint32_t msg_size = vec_bytes[4] * 16777216 + vec_bytes[3] * 65536 + vec_bytes[2] * 256 + vec_bytes[1];
    if(data_length - 5 == msg_size){
      auto it = vec_bytes.begin();
      vec_bytes.erase(it, it + 5);
    }
    else{
      return false;
    }
  }
  else{
    uint64_t msg_size = vec_bytes[8] * pow(2, 56) + vec_bytes[7] * pow(2, 48) + vec_bytes[6] * pow(2, 40) + vec_bytes[5] * 4294967296 + vec_bytes[4] * 16777216 + vec_bytes[3] * 65536 + vec_bytes[2] * 256 + vec_bytes[1];
    if(data_length - 9 == msg_size){
     auto it = vec_bytes.begin();
      vec_bytes.erase(it, it + 9);
    }
    else{
      return false;
    }
  }
  return true;
}

bool ambr::syn::SynManager::Impl::Init(const SynManagerConfig &config){
  config_ = std::move(config);
  try{
    SelectParams(gArgs.GetChainName(), config.listen_port_);
  }
  catch(const std::exception& e) {
    LOG(INFO)<< "Error : " << e.what();
    return false;
  }

  CConnman::Options connOptions;
  connOptions.vSeedNodes = config.vec_seed_;
  connOptions.nListenPort = config.listen_port_;
  connOptions.nMaxConnections = MAX_CONNECTIONS;
  connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
  connOptions.nLocalServices = ServiceFlags(NODE_NETWORK | NODE_WITNESS);
  connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);

  connOptions.DoAccept = std::bind(&ambr::syn::SynManager::Impl::OnAcceptNode, this, std::placeholders::_1);
  connOptions.DoConnect = std::bind(&ambr::syn::SynManager::Impl::OnConnectNode, this, std::placeholders::_1);
  connOptions.DoDisConnect = std::bind(&ambr::syn::SynManager::Impl::OnDisConnectNode, this, std::placeholders::_1);
  connOptions.DoReceiveNewMsg = std::bind(&ambr::syn::SynManager::Impl::OnReceiveNode, this,std::placeholders::_1, std::placeholders::_2);
  connOptions.DoGetLastNonce = std::bind(&ambr::store::StoreManager::GetLastValidatedUnitNonce, p_storemanager_);
  exit_ = false;

  dynasty_timer_.expires_from_now(boost::posix_time::milliseconds(dynasty_timer_value_));
  dynasty_timer_.async_wait(boost::bind(&ambr::syn::SynManager::Impl::IosDenastySyn, this, _1));
  ios_thread = std::thread(std::bind(&ambr::syn::SynManager::Impl::IoServiceThread, this));
  return ambr::p2p::init(std::move(connOptions));

}

void ambr::syn::SynManager::Impl::SendMessage(CSerializedNetMsg&& msg, CNode* p_node){
  if(p_node){
     ambr::p2p::SendMessage(p_node, std::forward<CSerializedNetMsg>(msg));
  }
}

void ambr::syn::SynManager::Impl::SetOnAccept(const std::function<void(CNode*)>& func){
 on_accept_node_func_ = func;
}

void ambr::syn::SynManager::Impl::SetOnConnected(const std::function<void(CNode*)>& func){
  on_connect_node_func_ = func;
}

void ambr::syn::SynManager::Impl::SetOnDisconnect(const std::function<void(CNode*)>& func){
  on_disconnect_node_func_ = func;
}

void ambr::syn::SynManager::Impl::BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node){
    ambr::p2p::BroadcastMessage(std::forward<CSerializedNetMsg>(msg));
}

bool ambr::syn::SynManager::Impl::OnReceiveNode(const CNetMessage& netmsg, CNode* p_node){
    std::string&& tmp = netmsg.hdr.GetCommand();
    if(NetMsgType::REQUESTDYNASTY == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());
      UnSerialize(buf);
      ambr::core::UnitHash validator_hash;
      validator_hash.decode_from_hex(std::string((const char*)buf.data(), buf.size()));
      ambr::core::UnitHash validator_hash_next_ = p_storemanager_->GetNextValidatorHash(validator_hash);
      if(validator_hash_next_.is_zero())return true;
      if(!p_storemanager_->GetValidateUnit(validator_hash_next_)->is_validate())return true;
      std::list<std::shared_ptr<ambr::core::Unit> >unit_list = p_storemanager_->GetAllUnitByValidatorUnitHash(validator_hash_next_);
      std::vector<std::vector<uint8_t>> unit_list_buf;
      //unit_list_buf.resize(unit_list.size());
      size_t idx = 0;
      size_t buf_count = 0;
      for(std::shared_ptr<ambr::core::Unit> unit_item: unit_list){
        std::vector<uint8_t> unit_buf = unit_item->SerializeByte();
        uint32_t type = (uint32_t)unit_item->type();
        unit_buf.insert(unit_buf.begin(), (char*)&type, (char*)(&type+1));
        unit_list_buf.push_back(unit_buf);
        buf_count += unit_list_buf[idx].size()+sizeof(uint64_t);
        idx++;
      }
      std::string str_buf(buf_count, 0);
      idx = 0;
      for(const std::vector<uint8_t> &buf_item: unit_list_buf){
        uint64_t len = buf_item.size();
        memcpy((char*)str_buf.data()+idx, &len, sizeof(len));
        idx += sizeof(len);
        memcpy((char*)str_buf.data()+idx, buf_item.data(), buf_item.size());
        idx+=buf_item.size();
      }
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::RESPONCEDYNASTY, str_buf), p_node);
    }else if(NetMsgType::RESPONCEDYNASTY == tmp){
      if(p_node != node_sync_ || is_sync_ != true){
        return false;
      }
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());
      UnSerialize(buf);
      bool right = true;
      uint64_t idx = 0;
      while(right){
        uint64_t size = 0;
        if(buf.size() - idx < sizeof(size))return true;
        memcpy(&size, buf.data()+idx, sizeof(size));
        idx+=sizeof(size);
        if(size <= sizeof(uint32_t)){
          return true;
        }

        uint32_t type = 0;
        if(buf.size() - idx < sizeof(type))return true;
        memcpy(&type, buf.data()+idx, sizeof(type));
        idx+=sizeof(type);
        std::shared_ptr<ambr::core::Unit> unit;
        switch((ambr::core::UnitType)type){
          //TODO:efficiency should improve
          case ambr::core::UnitType::send:unit = std::make_shared<ambr::core::SendUnit>();break;
          case ambr::core::UnitType::receive:unit = std::make_shared<ambr::core::ReceiveUnit>();break;
          case ambr::core::UnitType::Vote:unit = std::make_shared<ambr::core::VoteUnit>();break;
          case ambr::core::UnitType::Validator:unit = std::make_shared<ambr::core::ValidatorUnit>();break;
          case ambr::core::UnitType::EnterValidateSet:unit = std::make_shared<ambr::core::EnterValidateSetUnit>();break;
          case ambr::core::UnitType::LeaveValidateSet:unit = std::make_shared<ambr::core::LeaveValidateSetUnit>();break;
          default:
            return true;
        }
        std::vector<uint8_t> buf_tmp;
        buf_tmp.resize(size-sizeof(type));
        if(buf.size() - idx < size - sizeof(type))return true;
        memcpy(buf_tmp.data(), buf.data()+idx, buf_tmp.size());
        if(!unit->DeSerializeByte(buf_tmp, nullptr)){
          return true;
        }
        idx+=buf_tmp.size();
        p_storemanager_->AddUnitToBuffer(unit);

      }
    }
    return false;
}

void ambr::syn::SynManager::Impl::ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node){
    /*if(p_unit){
      if(!p_unit->prev_unit().is_zero() && nullptr == p_storemanager_->GetUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        p_storemanager_->GetLastUnitHashByPubKey(p_unit->public_key(), hash);
        std::string&& str_hash = hash.encode_to_hex();

        LOG(INFO) << "to request account unit: " << str_hash;
        SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTACCOUNTUNIT, str_hash), p_node);
      }
      else{
        p_storemanager_->AddUnitToBuffer(p_unit, (void*)p_node);
        //LOG(INFO) << "add unit: " ;
      }
    }*/
}

void ambr::syn::SynManager::Impl::ReturnUnit(const std::vector<uint8_t>& buf, CNode* p_node){
  /*std::string str_tmp;
  str_tmp.assign(buf.begin(), buf.end());
  ambr::core::UnitHash hash;
  hash.decode_from_hex(str_tmp);

  std::shared_ptr<ambr::store::UnitStore> p_store = p_storemanager_->GetUnit(hash);
  if(p_store){
    switch (p_store->type()) {
    case ambr::store::UnitStore::ST_SendUnit:
    {
        auto p_sendunitstore = std::dynamic_pointer_cast<ambr::store::SendUnitStore>(p_store);
        std::shared_ptr<ambr::core::Unit> p_sendunit = p_sendunitstore->GetUnit();
        if(p_sendunit){
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, p_sendunit->SerializeByte()), p_node);
        }
        break;
    }
    case ambr::store::UnitStore::ST_ReceiveUnit:
    {
        auto p_receiveunitstore = std::dynamic_pointer_cast<ambr::store::ReceiveUnitStore>(p_store);
        std::shared_ptr<ambr::core::Unit> p_receiveunit = p_receiveunitstore->GetUnit();
        if(p_receiveunit){
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, p_receiveunit->SerializeByte()), p_node);
        }
        break;
    }
    case ambr::store::UnitStore::ST_EnterValidatorSet:
    {
        auto p_enterunitstore = std::dynamic_pointer_cast<ambr::store::EnterValidatorSetUnitStore>(p_store);
        std::shared_ptr<ambr::core::Unit> p_enterunit = p_enterunitstore->GetUnit();
        if(p_enterunit){
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, p_enterunit->SerializeByte()), p_node);
        }
        break;
    }
    case ambr::store::UnitStore::ST_LeaveValidatorSet:
    {
        auto p_leaveunitstore = std::dynamic_pointer_cast<ambr::store::LeaveValidatorSetUnitStore>(p_store);
        std::shared_ptr<ambr::core::Unit> p_leaveunit = p_leaveunitstore->GetUnit();
        if(p_leaveunit){
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, p_leaveunit->SerializeByte()), p_node);
        }
        break;
    }
    default:
        break;
    }
  }*/
}

void ambr::syn::SynManager::Impl::Shutdown(){
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    p_cconnman_->Stop();
}

void ambr::syn::SynManager::Impl::WaitForShutdown(){
    while (!ShutdownRequested())
    {
        MilliSleep(200);
    }
    p_cconnman_->Interrupt();
}

void ambr::syn::SynManager::Impl::IoServiceThread(){
  LOG(INFO)<<"syn io service is running";
  while(!exit_){
    ios_.run();
  }
}

void ambr::syn::SynManager::Impl::IosDenastySyn(const boost::system::error_code& ec){
  //if(!ec)
  {
    LOG(INFO)<<"syn denasty check";
    std::lock_guard<std::mutex> lk(nodes_mutex_);
    uint64_t newest_dynasty_nonce = 0;
    CNode* newest_node = nullptr;
    for(CNode* node: list_in_nodes_){
      if(node->latest_nonce > newest_dynasty_nonce){
        newest_dynasty_nonce = node->latest_nonce;
        newest_node = node;
      }
    }
    for(CNode* node: list_out_nodes_){
      if(node->latest_nonce > newest_dynasty_nonce){
        newest_dynasty_nonce = node->latest_nonce;
        newest_node = node;
      }
    }
    if(newest_dynasty_nonce > p_storemanager_->GetLastValidatedUnitNonce()){
      StartSyn(newest_node);
    }
    dynasty_timer_.expires_from_now(boost::posix_time::milliseconds(dynasty_timer_value_));
    dynasty_timer_.async_wait(boost::bind(&ambr::syn::SynManager::Impl::IosDenastySyn, this, boost::asio::placeholders::error));
  }
}

void ambr::syn::SynManager::Impl::OnAcceptNode(CNode* p_node){
  {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if(GetNodeCount() == 0){
      is_online_ = true;
    }
  }
  if(p_node){
    if(on_accept_node_func_){
      on_accept_node_func_(p_node);
    }
    std::lock_guard<std::mutex> lk(nodes_mutex_);
    list_in_nodes_.remove(p_node);
    list_in_nodes_.push_back(p_node);
  }
}

void ambr::syn::SynManager::Impl::OnConnectNode(CNode* p_node){
  {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if(GetNodeCount() == 0){
      is_online_ = true;
    }
  }
  if(p_node){
    if(on_connect_node_func_){
      on_connect_node_func_(p_node);
    }
    list_out_nodes_.remove(p_node);
    list_out_nodes_.push_back(p_node);
  }
}

void ambr::syn::SynManager::Impl::OnDisConnectNode(CNode* p_node){
    if(p_node && on_disconnect_node_func_){
      {
        std::lock_guard<std::mutex> lk(nodes_mutex_);
        list_in_nodes_.remove(p_node);
        list_out_nodes_.remove(p_node);
      }
      on_disconnect_node_func_(p_node);
    }
    {
      std::lock_guard<std::mutex> lk(state_mutex_);
      if(GetNodeCount() == 0){
        is_online_ = false;
      }
    }
}


ambr::syn::SynManager::SynManager(Ptr_StoreManager p_storemanager)
  : p_impl_(new Impl(p_storemanager))
  , p_storemanager_(p_storemanager){

}

void ambr::syn::SynManager::OnAcceptNode(CNode* p_node){
  p_impl_->OnAcceptNode(p_node);
}

void ambr::syn::SynManager::OnConnectNode(CNode* p_node){
  p_impl_->OnConnectNode(p_node);
}

void ambr::syn::SynManager::OnDisConnectNode(CNode* p_node){
  p_impl_->OnDisConnectNode(p_node);
}

bool ambr::syn::SynManager::Init(const ambr::syn::SynManagerConfig &config){
  return p_impl_->Init(config);
}

void ambr::syn::SynManager::RemoveNode(CNode* p_node, uint32_t second){
  p_impl_->RemoveNode(p_node, second);
}

bool ambr::syn::SynManager::OnReceiveNode(const CNetMessage& netmsg, CNode* p_node){
  return p_impl_->OnReceiveNode(netmsg, p_node);
}

void ambr::syn::SynManager::SetOnAcceptNode(const std::function<void(CNode*)>& func){
  p_impl_->SetOnAccept(func);
}

void ambr::syn::SynManager::SetOnConnectedNode(const std::function<void(CNode*)>& func){
  p_impl_->SetOnConnected(func);
}

void ambr::syn::SynManager::SetOnDisconnectNode(const std::function<void(CNode*)>& func){
  p_impl_->SetOnDisconnect(func);
}

void ambr::syn::SynManager::BoardCastNewSendUnit(std::shared_ptr<core::SendUnit> p_unit){
  /*std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);*/
}

void ambr::syn::SynManager::BoardCastNewVoteUnit(std::shared_ptr<ambr::core::VoteUnit> p_unit){

}

void ambr::syn::SynManager::BoardCastNewReceiveUnit(std::shared_ptr<core::ReceiveUnit> p_unit){

}

void ambr::syn::SynManager::BoardCastNewValidatorUnit(std::shared_ptr<core::ValidatorUnit> p_unit){

}

void ambr::syn::SynManager::BoardCastNewJoinValidatorSetUnit(std::shared_ptr<core::EnterValidateSetUnit> p_unit){

}

void ambr::syn::SynManager::BoardCastNewLeaveValidatorSetUnit(std::shared_ptr<core::LeaveValidateSetUnit> p_unit){

}

bool ambr::syn::SynManager::GetNodeIfPauseSend(const std::string &node_addr){
  return p_impl_->GetIfPauseSend(node_addr);
}

bool ambr::syn::SynManager::GetNodeIfPauseReceive(const std::string &node_addr){
  return p_impl_->GetIfPauseReceive(node_addr);
}
