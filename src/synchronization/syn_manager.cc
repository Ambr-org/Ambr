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

class ambr::syn::SynManager::Impl{
public:
  Impl(Ptr_StoreManager p_store_manager);

  void ReqDynastyNo();
  void InitDynastyNo();
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
  void ReqDynasty(const std::string& str_hash, CNode* p_node, Node_Timers_t* p_timers_);
  void InitDynasty(const std::string& str_hash, size_t pos, CNode* p_node);
  void ReqAccountUnit(const std::string& str_hash, CNode* p_node, Node_Timers_t* p_timers_);


  void ReturnDynastyNo(CNode* p_node);
  void ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node);
  void ReceiveDynastyNo(const uint64_t& num, CNode* p_node);
  void ReturnUnit(const std::vector<uint8_t>& buf, CNode* p_node);
  bool ReceiveValidatorUnit(const Ptr_Unit& p_unit, CNode* p_node);
  void ReceiveDynasty(const std::vector<uint8_t>& buf, CNode* p_node);
  void ReceiveNoDynasty(const std::string& strTmp, CNode* p_node);
  void ReturnDynasty(const std::vector<uint8_t>& buf, CNode* p_node);

private:
  void Shutdown();
  void WaitForShutdown();

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
  ambr::syn::SynState state_;
  boost::asio::io_service io_;
  boost::threadpool::pool tpool_;
  Ptr_StoreManager p_storemanager_;
  std::list<CNode*> list_in_nodes_;
  std::list<CNode*> list_out_nodes_;
  std::list<Ptr_Unit> list_ptr_unit_;
  ambr::syn::SynManagerConfig config_;
  ambr::core::UnitHash validator_hash_;
  boost::asio::deadline_timer dynastyno_timer_;
  Ptr_PeerLogicValidation p_peerLogicValidation_;
  std::map<CNode*, Node_Timers_t*> map_node_timer_;

  std::function<void(CNode*)> on_accept_node_func_;
  std::function<void(CNode*)> on_connect_node_func_;
  std::function<void(CNode*)> on_disconnect_node_func_;
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

ambr::syn::Node_Timers_t::Node_Timers_t()
  : num_dynastyno_(0)
  , num_accountunitno_(0)
  , dynasty_timer_(dynasty_io_, boost::posix_time::seconds(1))
  , accountunit_timer_(accountunit_io_, boost::posix_time::seconds(1)){
}

ambr::syn::SynManager::Impl::Impl(Ptr_StoreManager p_store_manager)
  : exit_(false)
  , num_dyn_no_(0)
  , num_node_no_(0)
  , p_max_no_node_(nullptr)
  , reqdynastyno_(0)
  , p_cconnman_(std::make_shared<CConnman>(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())))
  , p_scheduler(std::make_shared<CScheduler>())
  , tpool_(2)
  , p_storemanager_(p_store_manager)
  , dynastyno_timer_(io_, boost::posix_time::milliseconds(2000)){
}

uint32_t ambr::syn::SynManager::Impl::GetNodeCount(){
  return list_in_nodes_.size() + list_out_nodes_.size();
}

void ambr::syn::SynManager::Impl::ReqDynastyNo(){
  ++reqdynastyno_;
  LOG(INFO) << "req dynasty no";
  if(3 == reqdynastyno_){
    num_dyn_no_ = 0;
    reqdynastyno_ = 0;
    dynastyno_timer_.cancel();
    std::shared_ptr<ambr::store::ValidatorUnitStore> p_store = p_storemanager_->GetLastestValidateUnit();
    if(p_store){
      std::shared_ptr<ambr::core::Unit> p_unit = p_store->GetUnit();
      if(p_unit){
        InitDynasty(p_unit->hash().encode_to_hex(), 0, p_max_no_node_);
      }
    }
  }
  else{
    InitDynastyNo();
  }
}

void ambr::syn::SynManager::Impl::InitDynastyNo(){
  std::lock_guard<std::mutex> lk(state_mutex_);
  std::shared_ptr<ambr::store::ValidatorUnitStore> p_store = p_storemanager_->GetLastestValidateUnit();
  if(p_store){
    std::shared_ptr<ambr::core::Unit> p_unit = p_store->GetUnit();
    if(p_unit)
    {
      BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTYNO, p_unit->hash().encode_to_hex()), nullptr);
      dynastyno_timer_.async_wait(std::bind(&ambr::syn::SynManager::Impl::ReqDynastyNo, this));
      io_.run();
    }
  }
}

void ambr::syn::SynManager::Impl::AddListInNode(CNode *pnode){
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
  connOptions.DoGetLastNonce = std::bind(&ambr::store::StoreManager::GetLastValidateUnitNonce, p_storemanager_);
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
    if(NetMsgType::DYNASTY == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);LOG(INFO) << "dynasty size:" << buf.size();
      ReceiveDynasty(buf, p_node);
      //tpool_.schedule(std::bind(&ambr::syn::Impl::ReceiveDynasty, this, buf, p_node));
    }
    else if(NetMsgType::REQUESTDYNASTY == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      //ReturnDynasty(buf, p_node);
      tpool_.schedule(std::bind(&ambr::syn::SynManager::Impl::ReturnDynasty, this, buf, p_node));
    }
    else if(NetMsgType::DYNASTYNO == tmp){
      std::string strTmp;
      strTmp.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      ReceiveDynastyNo(atoi(strTmp.c_str()), p_node);
    }
    else if(NetMsgType::REQUESTDYNASTYNO == tmp){
      ReturnDynastyNo(p_node);
    }
    else if(NetMsgType::ACCOUNTUNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      ReceiveUnit(ambr::core::Unit::CreateUnitByByte(buf), p_node);
    }
    else if(NetMsgType::REQUESTACCOUNTUNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      ReturnUnit(buf, p_node);
    }
    else if(NetMsgType::NODYNASTY == tmp){
      std::string strTmp;
      strTmp.assign(netmsg.vRecv.begin() + 1, netmsg.vRecv.end());

      ReceiveNoDynasty(strTmp, p_node);
    }
    else if(NetMsgType::VALIDATORUNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      return ReceiveValidatorUnit(ambr::core::Unit::CreateUnitByByte(buf), p_node);
    }
    else if(NetMsgType::PING == tmp || NetMsgType::PONG==tmp){
      //LOG(INFO)<<"recieve ping or pong,nonce is "<<nonce;
    }
    else{
      //thread_pool_.schedule(boost::bind(on_receive_node_func_, msg, p_node));
    }
    return true;
}

void ambr::syn::SynManager::Impl::ReqDynasty(const std::string& str_hash, CNode* p_node, Node_Timers_t* p_timers_){
  if(p_timers_){
    if(3 <= p_timers_->num_dynastyno_++){
      p_timers_->num_dynastyno_ = 0;
      p_timers_->dynasty_timer_.cancel();
      LOG(INFO) << "cancel dynasty timer: " << str_hash;
    }
    else{
      std::stringstream ss;
      ss << "endambr";
      LOG(INFO) << "Req dynasty: " << ss.str() + str_hash << ", " << p_timers_->num_dynastyno_;
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, ss.str() + str_hash), p_node);
      p_timers_->dynasty_timer_.expires_at(p_timers_->dynasty_timer_.expires_at() + boost::posix_time::milliseconds(2000));
      p_timers_->dynasty_timer_.async_wait(boost::bind(&ambr::syn::SynManager::Impl::ReqDynasty, this, str_hash, p_node, p_timers_));
    }
  }
  else{
    LOG(INFO) << "no dynasty timer: " << str_hash;
  }
}

void ambr::syn::SynManager::Impl::InitDynasty(const std::string& str_hash, size_t pos, CNode* p_node){
  auto it = map_node_timer_.find(p_node);
  if(map_node_timer_.end() != it){
    std::stringstream ss; ss << pos << "ambr";
    Node_Timers_t* p_timers = it->second;
    SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, ss.str() + str_hash), p_node);
    LOG(INFO) << "to init dynasty: "  << ", " << str_hash;

    if(p_timers){
      p_timers->num_dynastyno_ = 0;
      p_timers->str_validator_hash_ = str_hash;
      p_timers->dynasty_timer_.async_wait(std::bind(&ambr::syn::SynManager::Impl::ReqDynasty, this, str_hash, p_node, p_timers));
      p_timers->dynasty_io_.run();
    }
  }
}

void ambr::syn::SynManager::Impl::ReqAccountUnit(const std::string& str_hash, CNode* p_node, Node_Timers_t* p_timers_){
  if(p_timers_){
    if(3 <= p_timers_->num_accountunitno_++){
      p_timers_->num_accountunitno_ = 0;
      p_timers_->accountunit_timer_.cancel();
      LOG(INFO) << "cancel account timer: " << str_hash;
    }
    else{
      LOG(INFO) << "Req dynasty: " << str_hash << ", " << p_timers_->num_accountunitno_;
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTACCOUNTUNIT, str_hash), p_node);
      p_timers_->accountunit_timer_.expires_at(p_timers_->accountunit_timer_.expires_at() + boost::posix_time::milliseconds(2000));
      p_timers_->accountunit_timer_.async_wait(std::bind(&ambr::syn::SynManager::Impl::ReqAccountUnit, this, str_hash, p_node, p_timers_));
    }
  }
  else{
    LOG(INFO) << "no acccount timer: " << str_hash;
  }
}

void ambr::syn::SynManager::Impl::ReturnDynastyNo(CNode* p_node){
  std::shared_ptr<ambr::store::ValidatorUnitStore> p_unit_store = p_storemanager_->GetLastestValidateUnit();
  if(p_unit_store){
    std::shared_ptr<ambr::core::Unit> p_unit = p_unit_store->GetUnit();
    if(p_unit){
      auto p_valunit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(p_unit);
      uint64_t num_val_no = p_valunit->nonce();
      std::stringstream ss;
      ss << num_val_no;

      std::vector<uint8_t> buf_data;
      std::string&& str_data = ss.str();
      buf_data.assign(str_data.begin(), str_data.end());
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::DYNASTYNO, buf_data), p_node);
    }
  }
}

void ambr::syn::SynManager::Impl::ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node){
    if(p_unit){
      Node_Timers_t* p_timers;
      auto it = map_node_timer_.find(p_node);
      if(map_node_timer_.end() != it){
        p_timers = it->second;
        if(p_timers && p_unit->hash().encode_to_hex() == p_timers->str_accountunit_hash_){
          p_timers->accountunit_timer_.cancel();
          LOG(INFO) << "cancel accountunit timer: " << p_unit->hash().encode_to_hex();
        }
      }
      //LOG(INFO) << "accountunit: " << p_unit->hash().encode_to_hex();

      if(!p_unit->prev_unit().is_zero() && nullptr == p_storemanager_->GetUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        p_storemanager_->GetLastUnitHashByPubKey(p_unit->public_key(), hash);
        std::string&& str_hash = hash.encode_to_hex();

        LOG(INFO) << "to request account unit: " << str_hash;
        SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTACCOUNTUNIT, str_hash), p_node);
        if(p_timers){
          p_timers->num_accountunitno_ = 0;
          p_timers->str_accountunit_hash_ = str_hash;
          p_timers->accountunit_timer_.async_wait(std::bind(&ambr::syn::SynManager::Impl::ReqAccountUnit, this, str_hash, p_node, p_timers));
          p_timers->accountunit_io_.run();
        }
      }
      else{

        p_storemanager_->AddUnitToBuffer(p_unit, (void*)p_node);
        //LOG(INFO) << "add unit: " ;
      }
      /*else if(ambr::core::UnitType::send == p_unit->type()){
        if(p_timers){
          p_timers->accountunit_timer_.cancel();
        }
        std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(p_unit);
        std::string str_data;
        if(send_unit && p_storemanager_->AddSendUnit(send_unit, &str_data)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
        else if(send_unit){
          LOG(INFO) << "add send unit failed: "  << ", " << send_unit->hash().encode_to_hex() << ", error: " << str_data;
        }
        else{
          LOG(INFO) << "send unit = nullptr: " ;
        }

        if(p_unit->prev_unit().is_zero())
        {
          LOG(INFO) << "account unit's prev unit is zero: " ;
        }
      }
      else if(ambr::core::UnitType::receive == p_unit->type()){
        if(p_timers){
          p_timers->accountunit_timer_.cancel();
        }
        std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(p_unit);
        std::string str_data;
        if(receive_unit && p_storemanager_->AddReceiveUnit(receive_unit, &str_data)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
        else if(receive_unit){
          LOG(INFO) << "add receive unit failed: "  << ", error: " << str_data;
        }
        else{
          LOG(INFO) << "receive unit = nullptr: " ;
        }
      }
      else if(ambr::core::UnitType::Vote == p_unit->type()){
        std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(p_unit);
        if(vote_unit && p_storemanager_->AddVote(vote_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }
      else if(ambr::core::UnitType::EnterValidateSet == p_unit->type()){
        if(p_timers){
          p_timers->accountunit_timer_.cancel();
        }
        std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(p_unit);
        if(enter_validator_unit && p_storemanager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }
      else if(ambr::core::UnitType::LeaveValidateSet == p_unit->type()){
        if(p_timers){
          p_timers->accountunit_timer_.cancel();
        }
        std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(p_unit);
        if(leave_validator_unit && p_storemanager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }*/
    }
}

void ambr::syn::SynManager::Impl::ReceiveDynastyNo(const uint64_t& num, CNode* p_node){
    std::lock_guard<std::mutex> lk(state_mutex_);
    ++num_node_no_;
    if(num_dyn_no_ < num){
      num_dyn_no_ = num;
      p_max_no_node_ = p_node;
    }

    if(GetNodeCount() <= num_node_no_){
      num_dyn_no_ = 0;
      num_node_no_ = 0;
      reqdynastyno_ = 0;
      dynastyno_timer_.cancel();
      std::shared_ptr<ambr::store::ValidatorUnitStore> p_store = p_storemanager_->GetLastestValidateUnit();
      if(p_store){
        std::shared_ptr<ambr::core::Unit> p_unit = p_store->GetUnit();
        if(p_unit){
          InitDynasty(p_unit->hash().encode_to_hex(), 0, p_max_no_node_);
        }
      }
    }
}

void ambr::syn::SynManager::Impl::ReturnUnit(const std::vector<uint8_t>& buf, CNode* p_node){
  std::string str_tmp;
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
  }
}

bool ambr::syn::SynManager::Impl::ReceiveValidatorUnit(const Ptr_Unit& p_unit, CNode* p_node){
    if(p_unit && !p_unit->prev_unit().is_zero()){
      if(nullptr == p_storemanager_->GetValidateUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        if(ambr::core::UnitType::Validator == p_unit->type()){
          if(p_storemanager_->GetLastValidateUnit(hash)){
            if(hash == validator_hash_){
              return false;
            }
            validator_hash_ = hash;
            InitDynasty(hash.encode_to_hex(), 0, p_node);
          }
        }
      }
      else{
          auto it = map_node_timer_.find(p_node);
          if(map_node_timer_.end() != it){
            Node_Timers_t* p_timers = it->second;
            if(p_timers){
              p_timers->num_dynastyno_ = 0;
              p_timers->dynasty_timer_.async_wait(std::bind(&ambr::syn::SynManager::Impl::ReqDynasty, this, p_unit->hash().encode_to_hex(), p_node, p_timers));
              p_timers->dynasty_io_.run();
            }
          }

          if(p_storemanager_->GetValidateUnit(p_unit->hash())){
            std::stringstream ss;  ss << 0 << "ambr";
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, ss.str() + p_unit->hash().encode_to_hex()), p_node);
            return false;
          }
          else
          {
            std::stringstream ss;  ss << 0 << "ambr";
            p_storemanager_->AddUnitToBuffer(p_unit, (void*)p_node);
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, ss.str() + p_unit->hash().encode_to_hex()), p_node);
            return true;
          }
      }
    }
    return false;
}

void ambr::syn::SynManager::Impl::ReceiveDynasty(const std::vector<uint8_t>& buf, CNode* p_node){
  if(0 < buf.size()){
    std::vector<uint8_t> buf_data;
    std::string str_hash, str_data = "end";
    LOG(INFO) << "dynasty begin: ";
    int i = 0;int length = 0;
    for(auto it = buf.begin(); buf.end() > it; it += length){
      length = *it++ * pow(2, 24) + *it++ * pow(2, 16) + *it++ * pow(2, 8) + *it++;

      buf_data.clear();
      buf_data.assign(it ,it + length);
      std::shared_ptr<ambr::core::Unit> p_unit = ambr::core::Unit::CreateUnitByByte(buf_data);
      if(p_unit && ambr::core::UnitType::Validator == p_unit->type()){
       str_hash = p_unit->hash().encode_to_hex();

        auto it_map = map_node_timer_.find(p_node);
        if(map_node_timer_.end() != it_map){
          Node_Timers_t* p_timers = it_map->second;
          if(p_timers && p_unit->prev_unit().encode_to_hex() == p_timers->str_validator_hash_){
            p_timers->dynasty_timer_.cancel();
            LOG(INFO) << "cancel dynasty timer: " << p_unit->prev_unit().encode_to_hex();
          }
        }

      LOG(INFO) << "dynasty validatorunit: "  << ", " << str_hash;
        if(!p_storemanager_->GetValidateUnit(p_unit->hash()) && p_storemanager_->GetValidateUnit(p_unit->prev_unit())){
          p_storemanager_->AddUnitToBuffer(p_unit, (void*)p_node);
          if(buf.end() == it){
            str_hash = "ambr" + str_hash;
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, str_data + str_hash), p_node);
            LOG(INFO) << "request dynasty: " << str_data + str_hash;
          }
        }
        else if(!p_storemanager_->GetValidateUnit(p_unit->prev_unit())){
          std::shared_ptr<ambr::store::ValidatorUnitStore> p_unitstore = p_storemanager_->GetLastestValidateUnit();
          if(p_unitstore){
            std::shared_ptr<ambr::core::Unit> p_val_unit = p_unitstore->GetUnit();
            if(p_val_unit){
              str_hash = "ambr" + p_val_unit->hash().encode_to_hex();
              SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, str_data + str_hash), p_node);
              LOG(INFO) << "dynasty return1: " << str_data + str_hash;
              return;
            }
          }
        }
        else if(p_storemanager_->GetValidateUnit(p_unit->hash())){
          LOG(INFO) << "dynasty return2: " << str_hash;
          return;
        }
      }
      else if(p_unit){
          LOG(INFO) << "dynasty accountunit: " << p_unit->hash().encode_to_hex() << ": " << i;
          p_storemanager_->AddUnitToBuffer(p_unit, (void*)p_node);
          LOG(INFO) << "dynasty accountunit: " << p_unit->hash().encode_to_hex() << ": " << ++i;
          if(buf.end() == it + length){
            str_hash = "ambr" + str_hash;
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, str_data + str_hash), p_node);
            LOG(INFO) << "invalidate unit: " << str_data + str_hash;
          }
      }
      else if(buf.begin() + 4 == it)
      {
         str_data.assign(buf_data.begin(), buf_data.end());
      }
      else
      {
         LOG(INFO) << "invalidate unit: " << str_hash << ", " << ++i;
      }
    }
    LOG(INFO) << "dynasty end: ";
  }
}

void ambr::syn::SynManager::Impl::ReceiveNoDynasty(const std::string& strTmp, CNode* p_node){
    ambr::core::UnitHash hash;
    hash.decode_from_hex(strTmp);

    std::shared_ptr<ambr::core::ValidatorUnit> p_unit;
    std::shared_ptr<ambr::store::ValidatorUnitStore> p_validator_unit_store = p_storemanager_->GetValidateUnit(hash);
    if(p_validator_unit_store){
      p_unit = p_validator_unit_store->unit();;
    }
    else{
      p_unit = nullptr;
    }

    if(p_unit){
      hash = p_unit->prev_unit();
      if(!hash.is_zero()){
        InitDynasty(hash.encode_to_hex(), 0, p_node);
      }
    }
}

void ambr::syn::SynManager::Impl::ReturnDynasty(const std::vector<uint8_t>& buf, CNode* p_node){
    size_t num = 0;
    std::string str_error, str_data;
    str_data.assign(buf.begin(), buf.end());
    ambr::core::UnitHash in_hash, out_hash;

    size_t pos = str_data.find("ambr");
    std::string str_hash = str_data.substr(pos + 4);
    std::string str_begin = str_data.substr(0, pos);

    in_hash.decode_from_hex(str_hash);
    if(!p_storemanager_->GetNextValidatorHashByHash(in_hash, out_hash, &str_error)){
      return;
    }

    LOG(INFO) << "in hash:"  << in_hash.encode_to_hex() << "out hash:"  << out_hash.encode_to_hex() << ", begin: " << str_begin << ", num: " <<num;
    if(p_storemanager_->GetValidateUnit(in_hash)){
        std::shared_ptr<ambr::store::ValidatorUnitStore> p_unitstore = p_storemanager_->GetValidateUnit(out_hash);
        if(p_unitstore){
         std::shared_ptr<ambr::core::Unit> p_unit = p_unitstore->GetUnit();
          if(p_unit){
            std::vector<uint8_t> buf_data; size_t counter = 0;
            std::vector<uint8_t>&& vec_val_unit = p_unit->SerializeByte();
            uint32_t length = vec_val_unit.size();
            buf_data.push_back((uint8_t)((length >> 24)& 0xff));
            buf_data.push_back((uint8_t)((length >> 16)& 0xff));
            buf_data.push_back((uint8_t)((length >> 8)& 0xff));
            buf_data.push_back((uint8_t)(length& 0xff));
            buf_data.insert(buf_data.end(), vec_val_unit.begin(), vec_val_unit.end());

            if(!p_unit->prev_unit().is_zero()){
              std::list<std::shared_ptr<ambr::core::Unit>> list_p_units = p_storemanager_->GetAllUnitByValidatorUnitHash(out_hash);
              LOG(INFO) << "return dynasty begin:"  << in_hash.encode_to_hex();
              for(auto it : list_p_units){
                if(num < ++counter){
                  std::vector<uint8_t>&& vec_unit = it->SerializeByte();
                  int length = vec_unit.size();
                  buf_data.push_back((uint8_t)((length >> 24)& 0xff));
                  buf_data.push_back((uint8_t)((length >> 16)& 0xff));
                  buf_data.push_back((uint8_t)((length >> 8)& 0xff));
                  buf_data.push_back((uint8_t)(length& 0xff));
                  buf_data.insert(buf_data.end(), vec_unit.begin(), vec_unit.end());
                }
              }
            }

            std::stringstream ss;
            ss.str("");
            ss << "end";

            std::string&& str_tmp = ss.str();
            uint32_t len_str = str_tmp.size();
            buf_data.insert(buf_data.begin(), str_tmp.begin(), str_tmp.end());
            buf_data.insert(buf_data.begin(), (uint8_t)(len_str& 0xff));
            buf_data.insert(buf_data.begin(), (uint8_t)((len_str >> 8)& 0xff));
            buf_data.insert(buf_data.begin(), (uint8_t)((len_str >> 16)& 0xff));
            buf_data.insert(buf_data.begin(), (uint8_t)((len_str >> 24)& 0xff));

            LOG(INFO) << "return dynasty:"  << in_hash.encode_to_hex() << ", " << out_hash.encode_to_hex() << ": " << counter << " : " << buf_data.size();
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::DYNASTY, buf_data), p_node);
            LOG(INFO) << "return dynasty end:"  << in_hash.encode_to_hex();
          }
        }
    }
    else{
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::NODYNASTY, buf), p_node);
    }
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

void ambr::syn::SynManager::Impl::OnAcceptNode(CNode* p_node){
  {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if(GetNodeCount() == 0){
      state_.is_online_ = true;
    }
  }
  if(p_node){
    if(on_accept_node_func_){
      on_accept_node_func_(p_node);
    }
    list_in_nodes_.remove(p_node);
    list_in_nodes_.push_back(p_node);

    map_node_timer_.insert(std::pair<CNode*, Node_Timers_t*>(p_node, new Node_Timers_t()));
  }
}

void ambr::syn::SynManager::Impl::OnConnectNode(CNode* p_node){
  {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if(GetNodeCount() == 0){
      state_.is_online_ = true;
    }
  }
  if(p_node){
    if(on_connect_node_func_){
      on_connect_node_func_(p_node);
    }
    list_out_nodes_.remove(p_node);
    list_out_nodes_.push_back(p_node);

    map_node_timer_.insert(std::pair<CNode*, Node_Timers_t*>(p_node, new Node_Timers_t()));
    //std::thread initThread(&ambr::syn::Impl::RequestValidator, this);
    //initThread.detach();
  }
}

void ambr::syn::SynManager::Impl::OnDisConnectNode(CNode* p_node){
    if(p_node && on_disconnect_node_func_){
      list_in_nodes_.remove(p_node);
      list_out_nodes_.remove(p_node);
      on_disconnect_node_func_(p_node);
      auto it = map_node_timer_.find(p_node);
      if(map_node_timer_.end() != it){
        map_node_timer_.erase(it);
      }
    }
    {
      std::lock_guard<std::mutex> lk(state_mutex_);
      if(GetNodeCount() == 0){
        state_.is_online_ = false;
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
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewVoteUnit(std::shared_ptr<ambr::core::VoteUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewReceiveUnit(std::shared_ptr<core::ReceiveUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewValidatorUnit(std::shared_ptr<core::ValidatorUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());

  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VALIDATORUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewJoinValidatorSetUnit(std::shared_ptr<core::EnterValidateSetUint> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewLeaveValidatorSetUnit(std::shared_ptr<core::LeaveValidateSetUint> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

bool ambr::syn::SynManager::GetNodeIfPauseSend(const std::string &node_addr){
  return p_impl_->GetIfPauseSend(node_addr);
}

bool ambr::syn::SynManager::GetNodeIfPauseReceive(const std::string &node_addr){
  return p_impl_->GetIfPauseReceive(node_addr);
}
