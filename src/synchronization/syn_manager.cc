#include "p2p/net.h"
#include <p2p/init.h>
#include "netbase.h"
#include "shutdown.h"
#include "scheduler.h"
#include "syn_manager.h"
#include "chainparams.h"
#include "net_processing.h"
#include "netmessagemaker.h"

#include <list>
#include <functional>
#include <boost/bind.hpp>
#include <glog/logging.h>
#include <boost/thread.hpp>
#include <boost/threadpool.hpp>
#include <store/store_manager.h>

#define FIXED_RATE 70
#define MAX_CONNECTIONS 12
class ambr::syn::SynManager::Impl{
public:
  Impl(Ptr_StoreManager p_store_manager);

  uint32_t GetNodeCount();
  void RequestValidator();
  void AddListInNode(CNode *pnode);
  bool GetIfPauseSend(const std::string &addr);
  bool GetIfPauseReceive(const std::string &addr);
  void RemoveNode(CNode* p_node, uint32_t second);
  void UnSerialize(std::vector<uint8_t>& vec_bytes);
  bool Init(const ambr::syn::SynManagerConfig& config);
  void SendMessage(CSerializedNetMsg&& msg, CNode* p_node);
  void SetOnAccept(const std::function<void(CNode*)>& func);
  void SetOnConnected(const std::function<void(CNode*)>& func);
  void SetOnDisconnect(const std::function<void(CNode*)>& func);
  void BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node);

  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node);

private:
  void Shutdown();
  void WaitForShutdown();
  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisConnectNode(CNode* p_node);
  void ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node);
  bool ReceiveValidatorUnit(const Ptr_Unit& p_unit, CNode* p_node);
  void ReceiveAllUnit(const std::vector<uint8_t>& buf, CNode* p_node);
  void ReceiveNoValidatorUnit(const std::string& strTmp, CNode* p_node);
  void ReturnValidatorUnit(const std::vector<uint8_t>& buf, CNode* p_node);

private:
  bool exit_;
  std::mutex state_mutex_;
  Ptr_CConnman p_cconnman_;
  Ptr_CScheduler p_scheduler;
  ambr::syn::SynState state_;
  Ptr_StoreManager p_storemanager_;
  std::list<CNode*> list_in_nodes_;
  std::list<CNode*> list_out_nodes_;
  std::list<Ptr_Unit> list_ptr_unit_;
  ambr::syn::SynManagerConfig config_;
  Ptr_PeerLogicValidation p_peerLogicValidation_;

  std::function<void(CNode*)> on_accept_node_func_;
  std::function<void(CNode*)> on_connect_node_func_;
  std::function<void(CNode*)> on_disconnect_node_func_;
};


ambr::syn::SynManager::Impl::Impl(Ptr_StoreManager p_store_manager)
  : exit_(false)
  , p_cconnman_(std::make_shared<CConnman>(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())))
  , p_scheduler(std::make_shared<CScheduler>())
  , p_storemanager_(p_store_manager){

}

uint32_t ambr::syn::SynManager::Impl::GetNodeCount(){
  return list_in_nodes_.size()+list_out_nodes_.size();
}

void ambr::syn::SynManager::RequestValidator(){
  std::lock_guard<std::mutex> lk(state_mutex_);
  std::shared_ptr<ambr::store::ValidatorUnitStore> p_store = p_storemanager_->GetLastestValidateUnit();
  if(p_store){
    std::shared_ptr<ambr::core::Unit> p_unit = p_store->GetUnit();
    if(p_unit)
    {
      BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTVALUNIT, p_unit->hash().encode_to_hex()), nullptr);
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

void ambr::syn::SynManager::UnSerialize(std::vector<uint8_t>& vec_bytes){
  size_t data_length = vec_bytes.size();
  if(253 >= data_length && 0 < data_length){
    uint8_t msg_size = vec_bytes[0];
    if(data_length - 1 == msg_size){
      auto it = vec_bytes.begin();
      vec_bytes.erase(it);
    }
  }
  else if(std::numeric_limits<unsigned short>::max() + 3 >= data_length && 0 < data_length){
    uint16_t msg_size = vec_bytes[2] * 256 + vec_bytes[1];
    if(data_length - 3 == msg_size){
      auto it = vec_bytes.begin();
      for(int i = 0; i < 3; ++i){
        vec_bytes.erase(it);
      }
    }
  }
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
  p_peerLogicValidation_ = std::make_shared<PeerLogicValidation>(p_cconnman_.get(), *p_scheduler);
  p_peerLogicValidation_->AddOnAcceptCallback(std::bind(&ambr::syn::SynManager::Impl::OnAcceptNode, this, std::placeholders::_1));
  p_peerLogicValidation_->AddOnConnectCallback(std::bind(&ambr::syn::SynManager::Impl::OnConnectNode, this, std::placeholders::_1));
  p_peerLogicValidation_->AddOnDisConnectCallback(std::bind(&ambr::syn::SynManager::Impl::OnDisConnectNode, this, std::placeholders::_1));
  //p_peerLogicValidation_->AddOnMoreProcessCallback(std::bind(&ambr::syn::SynManager::Impl::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
  CConnman::Options connOptions;
  connOptions.nMaxConnections = MAX_CONNECTIONS;
  connOptions.nLocalServices = ServiceFlags(NODE_NETWORK | NODE_WITNESS);
  connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
  connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
  connOptions.m_msgproc = p_peerLogicValidation_.get();
  connOptions.vSeedNodes = config.vec_seed_;

  if(p_cconnman_->Start(*p_scheduler.get(), connOptions)){
    WaitForShutdown();
  }
  else{
    p_cconnman_->Interrupt();
  }
  Shutdown();
  return true;
}

void ambr::syn::SynManager::SendMessage(CSerializedNetMsg&& msg, CNode* p_node){
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

void ambr::syn::SynManager::BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node){
    ambr::p2p::BroadcastMessage(std::forward<CSerializedNetMsg>(msg));
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

    //std::thread initThread(&ambr::syn::SynManager::Impl::RequestValidator, this);
    //initThread.detach();
  }
}

void ambr::syn::SynManager::Impl::OnDisConnectNode(CNode* p_node){
    if(p_node && on_disconnect_node_func_){
      list_in_nodes_.remove(p_node);
      list_out_nodes_.remove(p_node);
      on_disconnect_node_func_(p_node);
    }
    {
      std::lock_guard<std::mutex> lk(state_mutex_);
      if(GetNodeCount() == 0){
        state_.is_online_ = false;
      }
    }
}

void ambr::syn::SynManager::ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node){
    if(p_unit){
      std::vector<uint8_t> buf;
      if(!p_unit->prev_unit().is_zero() && nullptr == p_storemanager_->GetUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        LOG(INFO) << "No last account unit:" << p_unit->SerializeJson();
        p_storemanager_->GetLastUnitHashByPubKey(p_unit->public_key(), hash);
        std::string&& str_data = hash.encode_to_hex();

        buf.assign(str_data.begin(), str_data.end());
        SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTACCOUNTLUNIT, buf), p_node);
      }
      else if(ambr::core::UnitType::send == p_unit->type()){
        std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(p_unit);
        if(send_unit && p_storemanager_->AddSendUnit(send_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }
      else if(ambr::core::UnitType::receive == p_unit->type()){
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
        std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(p_unit);
        if(enter_validator_unit && p_storemanager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }
      else if(ambr::core::UnitType::LeaveValidateSet == p_unit->type()){
        std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(p_unit);
        if(leave_validator_unit && p_storemanager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr)){
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, buf), p_node);
        }
      }
    }
}

bool ambr::syn::SynManager::ReceiveValidatorUnit(const Ptr_Unit& p_unit, CNode* p_node){
    if(p_unit && !p_unit->prev_unit().is_zero()){
      LOG(INFO) << "Receive Validator Unit Hash:" << p_unit->hash().encode_to_hex();
      if(nullptr == p_storemanager_->GetValidateUnit(p_unit->prev_unit())){
        ambr::core::UnitHash hash;
        if(ambr::core::UnitType::Validator == p_unit->type()){
          if(p_storemanager_->GetLastValidateUnit(hash)){
            SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTVALUNIT, hash.encode_to_hex()), p_node);
          }
        }
      }
      else{
        std::shared_ptr<ambr::core::ValidatorUnit> p_validatorunit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(p_unit);
        if(p_storemanager_->AddValidateUnit(p_validatorunit, nullptr)){
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTVALUNIT, p_unit->hash().encode_to_hex()), p_node);
          return true;
        }
      }
    }
    return false;
}

void ambr::syn::SynManager::ReceiveAllUnit(const std::vector<uint8_t>& buf, CNode* p_node){
    auto first = buf.begin();
    for(auto it = buf.begin(); buf.end() >= it; ++it){
      if(('a' == *it && 'm' == *(it + 1) && 'b' == *(it + 2) && 'r' == *(it + 3)) || buf.end() == it){
        std::vector<uint8_t> buf_data;
        buf_data.assign(first ,it);
        first = it + 4;
        if(buf.end() == it){
          ReceiveValidatorUnit(ambr::core::Unit::CreateUnitByByte(buf_data), p_node);
        }
        else{
          ReceiveUnit(ambr::core::Unit::CreateUnitByByte(buf_data), p_node);
        }
      }
    }
}

void ambr::syn::SynManager::ReceiveNoValidatorUnit(const std::string& strTmp, CNode* p_node){
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
        SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REQUESTVALUNIT, hash.encode_to_hex()), p_node);
      }
    }
}

void ambr::syn::SynManager::ReturnValidatorUnit(const std::vector<uint8_t>& buf, CNode* p_node){
    LOG(INFO) << "Get Validator Unit Hash:" << buf.data();
    std::string str_error, str_hash;
    str_hash.assign(buf.begin(), buf.end());
    ambr::core::UnitHash in_hash, out_hash;
    in_hash.decode_from_hex(str_hash);
    if(p_storemanager_->GetValidateUnit(in_hash))
    {
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
              SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ALLUNIT, buf_data), p_node);
            }
          }
      }
    }
    else{
      SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::NOVALIDATORUNIT, buf), p_node);
    }
}

bool ambr::syn::SynManager::OnReceiveNode(const CNetMessage& netmsg, CNode* p_node){
    std::string&& tmp = netmsg.hdr.GetCommand();
    if(NetMsgType::ALLUNIT == tmp){
        std::vector<uint8_t> buf;
        buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

        UnSerialize(buf);
        ReceiveAllUnit(buf, p_node);
    }
    else if(NetMsgType::ACCOUNTUNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      ReceiveUnit(ambr::core::Unit::CreateUnitByByte(buf), p_node);
    }
    else if(NetMsgType::NOVALIDATORUNIT == tmp){
      std::string strTmp;
      strTmp.assign(netmsg.vRecv.begin() + 1, netmsg.vRecv.end());
      ReceiveNoValidatorUnit(strTmp, p_node);
    }
    else if(NetMsgType::VALIDATORUNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      return ReceiveValidatorUnit(ambr::core::Unit::CreateUnitByByte(buf), p_node);
    }
    else if(NetMsgType::REQUESTVALUNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

      UnSerialize(buf);
      ReturnValidatorUnit(buf, p_node);
    }
    else{
      //thread_pool_.schedule(boost::bind(on_receive_node_func_, msg, p_node));
    }
    return true;
}

ambr::syn::SynManager::SynManager(Ptr_StoreManager p_storemanager)
  : p_impl_(new Impl(p_storemanager))
  , p_storemanager_(p_storemanager){

}


bool ambr::syn::SynManager::Init(const ambr::syn::SynManagerConfig &config){
  return p_impl_->Init(config);
}

void ambr::syn::SynManager::RemoveNode(CNode* p_node, uint32_t second){
  p_impl_->RemoveNode(p_node, second);
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
  CSerializedNetMsg  msg1 = CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data);
  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewReceiveUnit(std::shared_ptr<core::ReceiveUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
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
  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ALLUNIT, buf_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewJoinValidatorSetUnit(std::shared_ptr<core::EnterValidateSetUint> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewLeaveValidatorSetUnit(std::shared_ptr<core::LeaveValidateSetUint> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewVoteUnit(std::shared_ptr<ambr::core::VoteUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ACCOUNTUNIT, str_data), nullptr);
}

bool ambr::syn::SynManager::GetNodeIfPauseSend(const std::string &node_addr){
  return p_impl_->GetIfPauseSend(node_addr);
}

bool ambr::syn::SynManager::GetNodeIfPauseReceive(const std::string &node_addr){
  return p_impl_->GetIfPauseReceive(node_addr);
}
