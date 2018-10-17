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
#include <functional>
#include <boost/bind.hpp>
#include <glog/logging.h>
#include <boost/thread.hpp>
#include <boost/threadpool.hpp>
#include <store/store_manager.h>

#define FIXED_RATE 70
#define MAX_CONNECTIONS 12

//All of the scenarios
//1. Send unit delayed.
//2. Request unit failed.
//3. Wrong unit sequence
//4. randmise peers, dynasty,
//5. node, island,
//6. 硬分叉处理， ？？
//7. 消息太多cpu能力不足， 1. 加大内存， 2. 丢掉重传 
//8. 带宽太窄， 发布出去， 直接丢掉
 
ambr::syn::Node_Timers_t::Node_Timers_t(boost::asio::io_service& io)
  : reqdynastyno_(0)
  , reqaccountunitno_(0)
  , accountunit_timer_(io, boost::posix_time::milliseconds(2000))
  , dynasty_timer_(io, boost::posix_time::milliseconds(2000)){

}

ambr::syn::Impl::Impl(Ptr_StoreManager p_store_manager)
  : exit_(false)
  , num_dyn_no_(0)
  , num_node_no_(0)
  , p_max_no_node_(nullptr)
  , reqdynastyno_(0)
  , p_cconnman_(std::make_shared<CConnman>(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())))
  , p_scheduler(std::make_shared<CScheduler>())
  , p_storemanager_(p_store_manager)
  , dynastyno_timer_(io_, boost::posix_time::milliseconds(2000)){
  io_.run();
}

uint32_t ambr::syn::Impl::GetNodeCount(){
  return list_in_nodes_.size()+list_out_nodes_.size();
}

void ambr::syn::Impl::ReqDynastyNo(){
  ++reqdynastyno_;
  if(3 == reqdynastyno_){
    num_dyn_no_ = 0;
    reqdynastyno_ = 0;
    dynastyno_timer_.cancel();
    std::shared_ptr<ambr::store::ValidatorUnitStore> p_store = p_storemanager_->GetLastestValidateUnit();
    if(p_store){
      std::shared_ptr<ambr::core::Unit> p_unit = p_store->GetUnit();
      if(p_unit){
        InitDynasty(p_unit->hash().encode_to_hex(), p_max_no_node_);
      }
    }
  }
  else{
    InitDynastyNo();
  }
}

void ambr::syn::Impl::InitDynastyNo(){
  std::lock_guard<std::mutex> lk(state_mutex_);
  std::shared_ptr<ambr::store::ValidatorUnitStore> p_store = p_storemanager_->GetLastestValidateUnit();
  if(p_store){
    std::shared_ptr<ambr::core::Unit> p_unit = p_store->GetUnit();
    if(p_unit)
    {
      BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTYNO, p_unit->hash().encode_to_hex()), nullptr);
      dynastyno_timer_.async_wait(std::bind(&ambr::syn::Impl::ReqDynastyNo, this));
    }
  }
}

void ambr::syn::Impl::AddListInNode(CNode *pnode){
  list_in_nodes_.push_back(pnode);
}

bool ambr::syn::Impl::GetIfPauseSend(const std::string &addr){
  return p_cconnman_->GetIfPauseSend(addr);
}

bool ambr::syn::Impl::GetIfPauseReceive(const std::string &addr){
  return p_cconnman_->GetIfPauseReceive(addr);
}

void ambr::syn::Impl::RemoveNode(CNode* p_node, uint32_t second){
  /*list_in_nodes_.remove(p_node);
  list_out_nodes_.remove(p_node);*/
  p_node->fDisconnect = true;
}

bool ambr::syn::Impl::UnSerialize(std::vector<uint8_t>& vec_bytes){
  size_t data_length = vec_bytes.size();
  if(253 >= data_length && 0 < data_length){
    uint8_t msg_size = vec_bytes[0];
    if(data_length - 1 == msg_size){
      auto it = vec_bytes.begin();
      vec_bytes.erase(it);
    }
    else{
      return false;
    }
  }
  else if(std::numeric_limits<unsigned short>::max() + 3 >= data_length && 0 < data_length){
    uint16_t msg_size = vec_bytes[2] * 256 + vec_bytes[1];
    if(data_length - 3 == msg_size){
      auto it = vec_bytes.begin();
      vec_bytes.erase(it, it + 3);
    }
    else{
      return false;
    }
  }
  return true;
}

bool ambr::syn::Impl::Init(const SynManagerConfig &config){
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

  connOptions.DoAccept = std::bind(&ambr::syn::Impl::OnAcceptNode, this, std::placeholders::_1);
  connOptions.DoConnect = std::bind(&ambr::syn::Impl::OnConnectNode, this, std::placeholders::_1);
  connOptions.DoDisConnect = std::bind(&ambr::syn::Impl::OnDisConnectNode, this, std::placeholders::_1);
  connOptions.DoReceiveNewMsg = std::bind(&ambr::syn::Impl::OnReceiveNode, this,std::placeholders::_1, std::placeholders::_2);
  return ambr::p2p::init(std::move(connOptions));

  /*struct in_addr addr_;
  std::string str_seed = config.vec_seed_.at(0);
  size_t num_pos = str_seed.find(":");
  std::string&& str_IP = str_seed.substr(0, num_pos);
  std::string&& str_port = str_seed.substr(num_pos + 1, str_seed.size());
  auto s =inet_pton(AF_INET, str_IP.c_str(), &addr_);
  if(1 != s){
    return false;
  }

  std::vector<CAddress> addrs;
  int num_port = atoi(str_port.c_str());
  CAddress addr(CService(addr_ , num_port), NODE_NONE);
  addrs.push_back(addr);

  p_cconnman_->AddNewAddresses(addrs, CAddress());

  if(p_cconnman_->Start(*p_scheduler.get(), connOptions)){
    WaitForShutdown();
  }
  else{
    p_cconnman_->Interrupt();
  }
  Shutdown();
  return true;*/
}

void ambr::syn::Impl::SendMessage(CSerializedNetMsg&& msg, CNode* p_node){
  if(p_node){
       ambr::p2p::SendMessage(p_node, std::forward<CSerializedNetMsg>(msg));
  }
}

void ambr::syn::Impl::SetOnAccept(const std::function<void(CNode*)>& func){
 on_accept_node_func_ = func;
}

void ambr::syn::Impl::SetOnConnected(const std::function<void(CNode*)>& func){
  on_connect_node_func_ = func;
}

void ambr::syn::Impl::SetOnDisconnect(const std::function<void(CNode*)>& func){
  on_disconnect_node_func_ = func;
}

void ambr::syn::Impl::BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node){
    ambr::p2p::BroadcastMessage(std::forward<CSerializedNetMsg>(msg));
}

bool ambr::syn::Impl::OnReceiveNode(const CNetMessage& netmsg, CNode* p_node){
    std::string&& tmp = netmsg.hdr.GetCommand();
    if(NetMsgType::DYNASTY == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      ReceiveDynasty(buf, p_node);
    }
    else if(NetMsgType::REQUESTDYNASTY == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      ReturnDynasty(buf, p_node);
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
    else{
      //thread_pool_.schedule(boost::bind(on_receive_node_func_, msg, p_node));
    }
    return true;
}

void ambr::syn::Impl::ReqDynasty(const std::vector<uint8_t>& buf, CNode* p_node){
  auto it = map_node_timer_.find(p_node);
  if(map_node_timer_.end() != it){
    Node_Timers_t* p_timers = it->second;
    p_timers->reqdynastyno_++;
    if(3 == p_timers->reqdynastyno_){
      p_timers->reqdynastyno_ = 0;
      p_timers->dynasty_timer_.cancel();
    }
    else{
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, buf), p_node);
    }
  }
}

void ambr::syn::Impl::InitDynasty(const std::string& str_data, CNode* p_node){
  auto it = map_node_timer_.find(p_node);
  if(map_node_timer_.end() != it){
    Node_Timers_t* p_timers = it->second;
    SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, str_data), p_node);

    std::vector<uint8_t> buf;
    buf.assign(str_data.begin(), str_data.end());
    p_timers->dynasty_timer_.async_wait(std::bind(&ambr::syn::Impl::ReqDynasty, this, buf, p_node));
  }
}

void ambr::syn::Impl::ReqAccountUnit(const std::vector<uint8_t>& buf, CNode* p_node){
  auto it = map_node_timer_.find(p_node);
  if(map_node_timer_.end() != it){
    Node_Timers_t* p_timers = it->second;
    p_timers->reqaccountunitno_++;
    if(3 == p_timers->reqaccountunitno_){
      p_timers->reqaccountunitno_ = 0;
      p_timers->accountunit_timer_.cancel();
    }
    else{
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTACCOUNTUNIT, buf), p_node);
    }
  }
}

void ambr::syn::Impl::ReturnDynastyNo(CNode* p_node){
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

void ambr::syn::Impl::ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node){
    if(p_unit){
      Node_Timers_t* p_timers;
      std::vector<uint8_t> buf;
      auto it = map_node_timer_.find(p_node);
      if(map_node_timer_.end() != it){
        p_timers = it->second;
      }
      if(!p_unit->prev_unit().is_zero() && nullptr == p_storemanager_->GetUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        LOG(INFO) << "No last account unit:" << p_unit->SerializeJson();
        p_storemanager_->GetLastUnitHashByPubKey(p_unit->public_key(), hash);
        std::string&& str_data = hash.encode_to_hex();

        buf.assign(str_data.begin(), str_data.end());
        SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTACCOUNTUNIT, buf), p_node);

        if(p_timers){
          p_timers->accountunit_timer_.async_wait(std::bind(&ambr::syn::Impl::ReqAccountUnit, this, buf, p_node));
        }
      }
      else if(ambr::core::UnitType::send == p_unit->type()){
        if(p_timers){
          p_timers->accountunit_timer_.cancel();
        }
        std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(p_unit);
        if(send_unit && p_storemanager_->AddSendUnit(send_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }
      else if(ambr::core::UnitType::receive == p_unit->type()){
        if(p_timers){
          p_timers->accountunit_timer_.cancel();
        }
        std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(p_unit);
        if(receive_unit && p_storemanager_->AddReceiveUnit(receive_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
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
      }
    }
}

void ambr::syn::Impl::ReceiveDynastyNo(const uint64_t& num, CNode* p_node){
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
          InitDynasty(p_unit->hash().encode_to_hex(), p_max_no_node_);
        }
      }
    }
}

void ambr::syn::Impl::ReturnUnit(const std::vector<uint8_t>& buf, CNode* p_node){
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

bool ambr::syn::Impl::ReceiveValidatorUnit(const Ptr_Unit& p_unit, CNode* p_node){
    if(p_unit && !p_unit->prev_unit().is_zero()){
      LOG(INFO) << "Receive Validator Unit Hash:" << p_unit->hash().encode_to_hex();
      if(nullptr == p_storemanager_->GetValidateUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        if(ambr::core::UnitType::Validator == p_unit->type()){
          if(p_storemanager_->GetLastValidateUnit(hash)){
            InitDynasty(hash.encode_to_hex(), p_node);
          }
        }
      }
      else{
        std::shared_ptr<ambr::core::ValidatorUnit> p_validatorunit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(p_unit);
        if(p_storemanager_->AddValidateUnit(p_validatorunit, nullptr)){
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTDYNASTY, p_unit->hash().encode_to_hex()), p_node);
          return true;
        }
      }
    }
    return false;
}

void ambr::syn::Impl::ReceiveDynasty(const std::vector<uint8_t>& buf, CNode* p_node){
  if(0 < buf.size()){
    auto first = buf.begin();
    for(auto it = buf.begin(); buf.end() >= it; ++it){
      if(('a' == *it && 'm' == *(it + 1) && 'b' == *(it + 2) && 'r' == *(it + 3)) || buf.end() == it){
        std::vector<uint8_t> buf_data;
        buf_data.assign(first ,it);
        first = it + 4;
        std::shared_ptr<ambr::core::Unit> p_unit = ambr::core::Unit::CreateUnitByByte(buf_data);
        if(p_unit && ambr::core::UnitType::Validator == p_unit->type()){
          ReceiveValidatorUnit(p_unit, p_node);
        }
        else if(p_unit){
          ReceiveUnit(p_unit, p_node);
        }
      }
    }
  }
}

void ambr::syn::Impl::ReceiveNoDynasty(const std::string& strTmp, CNode* p_node){
    LOG(INFO) << "Get No Validator Unit:" << strTmp;
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
        InitDynasty(hash.encode_to_hex(), p_node);
      }
    }
}

void ambr::syn::Impl::ReturnDynasty(const std::vector<uint8_t>& buf, CNode* p_node){
    LOG(INFO) << "Get Validator Unit Hash:" << buf.data();
    std::string str_error, str_hash;
    str_hash.assign(buf.begin(), buf.end());
    ambr::core::UnitHash in_hash, out_hash;
    in_hash.decode_from_hex(str_hash);
    if(p_storemanager_->GetValidateUnit(in_hash)){
      if(p_storemanager_->GetNextValidatorHashByHash(in_hash, out_hash, &str_error)){
        std::shared_ptr<ambr::store::ValidatorUnitStore> p_unitstore = p_storemanager_->GetValidateUnit(out_hash);
        if(p_unitstore){
         std::shared_ptr<ambr::core::Unit> p_unit = p_unitstore->GetUnit();
          if(p_unit){
            std::vector<uint8_t> buf_data;
            if(!p_unit->prev_unit().is_zero()){
              std::list<std::shared_ptr<ambr::core::Unit>> list_p_units = p_storemanager_->GetAllUnitByValidatorUnitHash(p_unit->hash());
              for(auto& it:list_p_units){
                std::vector<uint8_t>&& unit_buf = it->SerializeByte();
                if(!buf_data.empty()){
                  buf_data.push_back('a');
                  buf_data.push_back('m');
                  buf_data.push_back('b');
                  buf_data.push_back('r');
                }
                buf_data.insert(buf_data.end(), unit_buf.begin(), unit_buf.end());

              }
                buf_data.push_back('a');
                buf_data.push_back('m');
                buf_data.push_back('b');
                buf_data.push_back('r');
            }

            std::vector<uint8_t>&& unit_buf = p_unit->SerializeByte();
            buf_data.insert(buf_data.end(), unit_buf.begin(), unit_buf.end());
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::DYNASTY, buf_data), p_node);
          }
        }
      }
    }
    else{
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::NODYNASTY, buf), p_node);
    }
}

void ambr::syn::Impl::Shutdown(){
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    p_cconnman_->Stop();
}

void ambr::syn::Impl::WaitForShutdown(){
    while (!ShutdownRequested())
    {
        MilliSleep(200);
    }
    p_cconnman_->Interrupt();
}

void ambr::syn::Impl::OnAcceptNode(CNode* p_node){
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

    map_node_timer_.insert(std::pair<CNode*, Node_Timers_t*>(p_node, new Node_Timers_t(io_)));
  }
}

void ambr::syn::Impl::OnConnectNode(CNode* p_node){
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

    map_node_timer_.insert(std::pair<CNode*, Node_Timers_t*>(p_node, new Node_Timers_t(io_)));
    //std::thread initThread(&ambr::syn::Impl::RequestValidator, this);
    //initThread.detach();
  }
}

void ambr::syn::Impl::OnDisConnectNode(CNode* p_node){
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

  std::vector<uint8_t> buf_data;
  if(!p_unit->prev_unit().is_zero()){
    std::list<std::shared_ptr<ambr::core::Unit>> list_p_units = p_storemanager_->GetAllUnitByValidatorUnitHash(p_unit->hash());
    for(auto& it:list_p_units){
      std::vector<uint8_t>&& unit_buf = it->SerializeByte();
      if(!buf_data.empty()){
        buf_data.push_back('a');
        buf_data.push_back('m');
        buf_data.push_back('b');
        buf_data.push_back('r');
      }
      buf_data.insert(buf_data.end(), unit_buf.begin(), unit_buf.end());
    }
    buf_data.push_back('a');
    buf_data.push_back('m');
    buf_data.push_back('b');
    buf_data.push_back('r');
  }

  std::vector<uint8_t>&& unit_buf = p_unit->SerializeByte();
  buf_data.insert(buf_data.end(), unit_buf.begin(), unit_buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::DYNASTY, buf_data), nullptr);
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
