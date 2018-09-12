#include "p2p/net.h"
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
class ambr::syn::SynManager::Impl : public CConnman{
public:
  Impl(Ptr_StoreManager p_store_manager);
  bool Init(const SynManagerConfig& config);
  void RemoveNode(CNode* p_node, uint32_t second);
  void SendMessage(CSerializedNetMsg&& msg, CNode* p_node);
  void SetOnAccept(const std::function<void(CNode*)>& func);
  void SetOnConnected(const std::function<void(CNode*)>& func);
  void SetOnDisconnect(const std::function<void(CNode*)>& func);
  void BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node);

  void AddListInNode(CNode *pnode){
    list_in_nodes_.push_back(pnode);
  }
  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node);
  void UnSerialize(std::vector<uint8_t>& vec_bytes);
private:
  void Shutdown();
  void WaitForShutdown();
  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisConnectNode(CNode* p_node);
private:
  bool exit_;
  SynManagerConfig config_;
  Ptr_CScheduler p_scheduler;
  Ptr_StoreManager p_storemanager_;
  std::list<CNode*> list_in_nodes_;
  std::list<CNode*> list_out_nodes_;
  std::list<Ptr_Unit> list_ptr_unit_;
  std::list<CNode*> list_in_nodes_wait_;
  std::list<CNode*> list_out_nodes_wait_;
  Ptr_PeerLogicValidation p_peerLogicValidation_;

  std::function<void(CNode*)> on_accept_node_func_;
  std::function<void(CNode*)> on_connect_node_func_;
  std::function<void(CNode*)> on_disconnect_node_func_;
};


ambr::syn::SynManager::Impl::Impl(Ptr_StoreManager p_store_manager)
  : exit_(false)
  , p_storemanager_(p_store_manager)
  , p_scheduler(std::make_shared<CScheduler>())
  , CConnman(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())){

}

bool ambr::syn::SynManager::Impl::Init(const SynManagerConfig &config){
  config_ = std::move(config);
  SetAcceptFunc(std::bind(&ambr::syn::SynManager::Impl::OnAcceptNode, this, std::placeholders::_1));
  SetConnectFunc(std::bind(&ambr::syn::SynManager::Impl::OnConnectNode, this, std::placeholders::_1));

  try{
    SelectParams(gArgs.GetChainName(), config.listen_port_);
  }
  catch(const std::exception& e) {
    LOG(INFO)<< "Error : " << e.what();
    return false;
  }
  p_peerLogicValidation_ = std::make_shared<PeerLogicValidation>(this, *p_scheduler);

  CConnman::Options connOptions;
  connOptions.nMaxConnections = MAX_CONNECTIONS;
  connOptions.nLocalServices = ServiceFlags(NODE_NETWORK | NODE_WITNESS);
  connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
  connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
  connOptions.m_msgproc = p_peerLogicValidation_.get();
  connOptions.vSeedNodes = config.vec_seed_;
  /*connOptions.m_added_nodes = gArgs.GetArgs("-addnode");

  for (const std::string& strBind : gArgs.GetArgs("-bind")) {
      CService addrBind;
      if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false)) {
          std::cerr <<"Invalid -bind address or hostname: " << strBind << std::endl;
          return 1;
      }
      connOptions.vBinds.push_back(addrBind);
  }

  for (const std::string& strBind : gArgs.GetArgs("-whitebind")) {
      CService addrBind;
      if (!Lookup(strBind.c_str(), addrBind, 0, false)) {
            std::cerr <<"Invalid -whitebind address or hostname: " << strBind << std::endl;
            return 1;
      }
      if (addrBind.GetPort() == 0) {
            std::cerr <<"Invalid -whitebind address or hostname: "  << std::endl;
              return 1;
      }
      connOptions.vWhiteBinds.push_back(addrBind);
    }

  for (const auto& net : gArgs.GetArgs("-whitelist")) {
      CSubNet subnet;
      LookupSubNet(net.c_str(), subnet);
      if (!subnet.IsValid()){
          std::cerr <<"Invalid netmask specified in -whitelist: "  << net << std::endl;
          return 1;
      }

      connOptions.vWhitelistedRange.push_back(subnet);
  }

  connOptions.vSeedNodes = gArgs.GetArgs("-seednode");
*/
 /* std::vector<CAddress> vec_addrs;
  for(auto& it : config.vec_seed_){
    struct in_addr addr_;
    if(1 != inet_pton(AF_INET, "127.0.0.1", &addr_)){
      LOG(INFO) << "convert failed";
      return false;
    }
    CAddress addr(CService(addr_, atoi(it.c_str())), NODE_NONE);
    vec_addrs.push_back(addr);
  }

  AddNewAddresses(vec_addrs, CAddress());*/

  if(Start(*p_scheduler.get(), connOptions)){
    WaitForShutdown();
  }
  else{
    Interrupt();
  }
  Shutdown();
  return true;
}

void ambr::syn::SynManager::Impl::RemoveNode(CNode* p_node, uint32_t second){
  list_in_nodes_.remove(p_node);
  list_out_nodes_.remove(p_node);
}

void ambr::syn::SynManager::Impl::SendMessage(CSerializedNetMsg&& msg, CNode* p_node){
  if(p_node){
    PushMessage(p_node, std::forward<CSerializedNetMsg>(msg));
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
  for(auto it:list_in_nodes_){
    if(it != p_node){
      if(!it->fPauseSend){
        PushMessage(it, std::forward<CSerializedNetMsg>(msg));
      }
    }
  }
  for(auto it:list_out_nodes_){
    if(it != p_node){
      if(!it->fPauseSend){
        PushMessage(it, std::forward<CSerializedNetMsg>(msg));
      }else{
        int fordebug;
        fordebug = 1;
      }
    }
  }
}

void ambr::syn::SynManager::Impl::Shutdown(){
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    Stop();
}

void ambr::syn::SynManager::Impl::WaitForShutdown(){
    while (!ShutdownRequested())
    {
        MilliSleep(200);
    }
    Interrupt();
}

void ambr::syn::SynManager::Impl::OnAcceptNode(CNode* p_node){
  if(p_node){
    if(on_accept_node_func_){
      on_accept_node_func_(p_node);
    }
    list_in_nodes_wait_.remove(p_node);
    list_in_nodes_wait_.push_back(p_node);
    p_node->SetDisConnectNodeFunc(std::bind(&ambr::syn::SynManager::Impl::OnDisConnectNode, this, std::placeholders::_1));
    p_node->SetReceiveNodeFunc(std::bind(&ambr::syn::SynManager::Impl::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void ambr::syn::SynManager::Impl::OnConnectNode(CNode* p_node){
  if(p_node){
    if(on_connect_node_func_){
      on_connect_node_func_(p_node);
    }
    list_out_nodes_wait_.remove(p_node);
    list_out_nodes_wait_.push_back(p_node);
    p_node->SetDisConnectNodeFunc(std::bind(&ambr::syn::SynManager::Impl::OnDisConnectNode, this, std::placeholders::_1));
    p_node->SetReceiveNodeFunc(std::bind(&ambr::syn::SynManager::Impl::OnReceiveNode, this, std::placeholders::_1, std::placeholders::_2));
  }
}

void ambr::syn::SynManager::Impl::OnDisConnectNode(CNode* p_node){
    if(p_node && on_disconnect_node_func_){
      list_in_nodes_.remove(p_node);
      list_out_nodes_.remove(p_node);
      on_disconnect_node_func_(p_node);
    }
}

void ambr::syn::SynManager::Impl::UnSerialize(std::vector<uint8_t>& vec_bytes){
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

bool ambr::syn::SynManager::Impl::OnReceiveNode(const CNetMessage& netmsg, CNode* p_node){
    std::string&& tmp = netmsg.hdr.GetCommand();
    if(NetMsgType::VERSION == tmp){
      /*if(0x00000001 != msg->version_){
        LOG(WARNING) << "Error peer version:" << std::hex << std::setw(8) << std::setfill('0') << msg->version_
                     << "in" << p_node->GetAddrLocal().ToStringIP() << ":" << std::dec << std::setw(0) << p_node->GetAddrLocal().GetPort();
        RemoveNode(p_node, 0);
        list_in_nodes_.remove(p_node);
        list_out_nodes_.remove(p_node);
        list_in_nodes_wait_.remove(p_node);
        list_out_nodes_wait_.remove(p_node);
      }
      else*/
      {
        bool is_wait = false;
        for(auto& item : list_in_nodes_wait_){
        if(item == p_node){
            is_wait = true;
            list_in_nodes_wait_.remove(p_node);
            list_in_nodes_.push_back(p_node);
            LOG(INFO) << "Right node version:" << std::hex << std::setw(8) << std::setfill('0') << "save"
                      << p_node->GetAddrLocal().ToStringIP() << ":" << std::dec << std::setw(0) << p_node->GetAddrLocal().GetPort() << "to in_peers";
            break;
          }
        }

        for(auto& it:list_out_nodes_wait_){
          if(it == p_node){
            is_wait = true;
            list_out_nodes_wait_.remove(p_node);
            list_out_nodes_.push_back(p_node);
            LOG(INFO) << "Right node version:" << std::hex << std::setw(8) << std::setfill('0') << "save"
                      << p_node->GetAddrLocal().ToStringIP() << ":" << std::dec << std::setw(0) << p_node->GetAddrLocal().GetPort() << "to out_peers";
            //Send addr msg
            {
              SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::ADDR, ""), p_node);
              break;
            }
          }
        }
      }
    }
    else if(NetMsgType::ADDR == tmp){

    }
    else if(NetMsgType::UNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());
      UnSerialize(buf);
      Ptr_Unit unit = ambr::core::Unit::CreateUnitByByte(buf);
      LOG(INFO)<<"receive unit message";
      if(unit){
        LOG(INFO)<<"Unit create success:"<<unit->hash().encode_to_hex();
      }else{
        LOG(INFO)<<"Unit create faild";
      }
      if(unit){
        if(!unit->prev_unit().is_zero() && nullptr == p_storemanager_->GetUnit(unit->prev_unit()) && nullptr == p_storemanager_->GetValidateUnit(unit->prev_unit())){
          ambr::core::UnitHash hash;
          LOG(INFO) << "No last unit:" << unit->SerializeJson();
          if(ambr::core::UnitType::Validator == unit->type()){
            p_storemanager_->GetLastValidateUnit(hash);
          }
          else{
            p_storemanager_->GetLastUnitHashByPubKey(unit->public_key(), hash);
          }
          std::string str_data = hash.encode_to_hex() + ":" + unit->hash().encode_to_hex();

          buf.assign(str_data.begin(), str_data.end());
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::SECTION, buf), p_node);
        }
        else if(ambr::core::UnitType::send == unit->type()){
          std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
          if(send_unit && p_storemanager_->AddSendUnit(send_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::receive == unit->type()){
          std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
          if(receive_unit && p_storemanager_->AddReceiveUnit(receive_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::Vote == unit->type()){
          std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(unit);
          if(vote_unit && p_storemanager_->AddVote(vote_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::Validator == unit->type()){
          std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(unit);

          if(validator_unit){
            ambr::core::UnitHash newest_unithash;
            std::shared_ptr<ambr::core::ValidatorUnit> ptr_unit = nullptr;
            const ambr::core::UnitHash& last_unithash = validator_unit->prev_unit();

            if(p_storemanager_->GetLastValidateUnit(newest_unithash)){
              while(last_unithash != newest_unithash){
                ptr_unit = p_storemanager_->GetValidateUnit(newest_unithash);
                if(ptr_unit){
                  newest_unithash = ptr_unit->prev_unit();
                }
                else{
                  break;
                }
              }
            }

            if(last_unithash == newest_unithash){
              if(nullptr == ptr_unit){
                p_storemanager_->AddValidateUnit(validator_unit, nullptr);
                BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
              }
              else if(ptr_unit/* && FIXED_RATE <= validator_unit->percent()*/){
                /*p_storemanager_->RemoveUnit(ptr_unit->hash(), nullptr);*/ //remove by li
                p_storemanager_->AddValidateUnit(validator_unit, nullptr);
                BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
              }
            }
            else{
              if(p_storemanager_->AddValidateUnit(validator_unit, nullptr)){
                BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
              }
            }
          }
        }
        else if(ambr::core::UnitType::EnterValidateSet == unit->type()){
          std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(unit);
          if(enter_validator_unit && p_storemanager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::LeaveValidateSet == unit->type()){
          std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(unit);
          if(leave_validator_unit && p_storemanager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
      }
    }
    else if(NetMsgType::SECTION == tmp){
      std::string strTmp;
      strTmp.assign(netmsg.vRecv.begin() + 1, netmsg.vRecv.end());
      LOG(INFO)<<"Get New Section:"<< strTmp;
      ambr::core::UnitHash firsthash, lasthash;
      size_t num_pos = strTmp.find(':');
      if(num_pos != std::string::npos){
        firsthash.decode_from_hex(strTmp.substr(0, num_pos));
        lasthash.decode_from_hex(strTmp.substr(num_pos + 1, 64));

        std::list<Ptr_Unit> list_p_unit;
        while(firsthash != lasthash){
          Ptr_UnitStore p_unitstore = p_storemanager_->GetUnit(lasthash);

          Ptr_Unit p_unit;
          if(p_unitstore){
            p_unit = p_unitstore->GetUnit();
          }
          else{
            p_unit = p_storemanager_->GetValidateUnit(lasthash);
          }

          if(p_unit){
              list_p_unit.push_front(p_unit);
          }
          else{
              break;
          }

          Ptr_UnitStore p_prevunitstore = p_storemanager_->GetUnit(p_unit->prev_unit());

          Ptr_Unit p_prevunit;
          if(p_prevunitstore){
            p_prevunit = p_prevunitstore->GetUnit();
          }
          else{
            p_prevunit = p_storemanager_->GetValidateUnit(p_unit->prev_unit());
          }

          if(p_prevunit){
            lasthash = p_prevunit->hash();
          }
          else{
            break;
          }
        }

        for(auto& it:list_p_unit){
          std::vector<uint8_t>&& buf = it->SerializeByte();
          std::string str_data;
          str_data.assign(buf.begin(), buf.end());
          SendMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::SECTIONUNIT, str_data), p_node);
        }
      }
    }
    else if(NetMsgType::SECTIONUNIT == tmp){
        std::vector<uint8_t> buf;
        buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());

        UnSerialize(buf);
        Ptr_Unit unit = ambr::core::Unit::CreateUnitByByte(buf);
        LOG(INFO)<<"receive unit message";
        if(unit){
          LOG(INFO)<<"Unit create success:"<<unit->hash().encode_to_hex();
        }else{
          LOG(INFO)<<"Unit create faild";
        }
        if(unit){
          switch (unit->type()) {
          case ambr::core::UnitType::send:
          {
            LOG(INFO)<<"Get send section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
            p_storemanager_->AddSendUnit(send_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::receive:
          {
              LOG(INFO)<<"Get receive section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
              p_storemanager_->AddReceiveUnit(receive_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::Vote:
          {
              LOG(INFO)<<"Get vote section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(unit);
              p_storemanager_->AddVote(vote_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::Validator:
          {
              LOG(INFO) << "Get validator unit:" << unit->SerializeJson();
              std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(unit);

              if(validator_unit){
                  ambr::core::UnitHash newest_unithash;
                  std::shared_ptr<ambr::core::Unit> ptr_unit = nullptr;
                  const ambr::core::UnitHash& last_unithash = validator_unit->prev_unit();

                  if(p_storemanager_->GetLastValidateUnit(newest_unithash)){
                    while(last_unithash != newest_unithash){
                      ptr_unit = p_storemanager_->GetValidateUnit(newest_unithash);
                      if(ptr_unit){
                        newest_unithash = ptr_unit->prev_unit();
                      }
                      else{
                        break;
                      }
                    }
                  }

                  if(last_unithash == newest_unithash){
                    if(nullptr == ptr_unit){
                      p_storemanager_->AddValidateUnit(validator_unit, nullptr);
                    }
                    else if(ptr_unit && FIXED_RATE <= validator_unit->percent()){
                      p_storemanager_->RemoveUnit(ptr_unit->hash(), nullptr);
                      p_storemanager_->AddValidateUnit(validator_unit, nullptr);
                    }
                  }
                  else{
                    p_storemanager_->AddValidateUnit(validator_unit, nullptr);
                  }
              }
          }
          break;
          case ambr::core::UnitType::EnterValidateSet:
          {
              LOG(INFO)<<"Get enter validator section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(unit);
              p_storemanager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::LeaveValidateSet:
          {
              LOG(INFO)<<"Get leave validator section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(unit);
              p_storemanager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr);
          }
          break;
          default:
          break;
          }
        }
    }
    else{
      //thread_pool_.schedule(boost::bind(on_receive_node_func_, msg, p_node));
    }
    return true;
}

ambr::syn::SynManager::SynManager(Ptr_StoreManager p_storemanager){
  p_impl_ = new Impl(p_storemanager);
}

bool ambr::syn::SynManager::Init(const ambr::syn::SynManagerConfig &config){
  return p_impl_->Init(config);
}

void ambr::syn::SynManager::RemovePeer(CNode* p_node, uint32_t second){
  p_impl_->RemoveNode(p_node, second);
}

void ambr::syn::SynManager::BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node){
  p_impl_->BoardcastMessage(std::forward<CSerializedNetMsg>(msg), p_node);
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
  CSerializedNetMsg  msg1 = CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data);
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewReceiveUnit(std::shared_ptr<core::ReceiveUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewValidatorUnit(std::shared_ptr<core::ValidatorUnit> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewJoinValidatorSetUnit(std::shared_ptr<core::EnterValidateSetUint> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data), nullptr);
}

void ambr::syn::SynManager::BoardCastNewLeaveValidatorSetUnit(std::shared_ptr<core::LeaveValidateSetUint> p_unit){
  std::vector<uint8_t>&& buf = p_unit->SerializeByte();
  std::string str_data;
  str_data.assign(buf.begin(), buf.end());
  p_impl_->BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data), nullptr);
}
