#include "p2p/net.h"
#include "netbase.h"
#include "shutdown.h"
#include "net_test.h"
#include "scheduler.h"
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

#define FixedRate 70
#define MaxConnections 12
using Ptr_CScheduler = std::shared_ptr<CScheduler>;
using Ptr_UnitStore = std::shared_ptr<ambr::store::UnitStore>;
using Ptr_PeerLogicValidation = std::shared_ptr<PeerLogicValidation>;

class ambr::net::NetManager::Impl : public CConnman{
public:
  Impl(std::shared_ptr<store::StoreManager> store_manager);
  bool init(const NetManagerConfig& config);
  void SetOnReceive(std::function<void(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer)> func);
  void SendMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer);
  void BoardcastMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer);
  void SetOnDisconnect(std::function<void(std::shared_ptr<Peer>)> func);
  void SetOnAccept(std::function<void(std::shared_ptr<Peer>)> func);
  void SetOnConnected(std::function<void(std::shared_ptr<Peer>)> func);
  void RemovePeer(std::shared_ptr<Peer> peer, uint32_t second);

  void RemoveNode(CNode* p_node, uint32_t second);
  void SendMessage(CSerializedNetMsg&& msg, CNode* p_node);
  void SetOnAccept(const std::function<void(CNode*)>& func);
  void SetOnConnected(const std::function<void(CNode*)>& func);
  void SetOnDisconnect(const std::function<void(CNode*)>& func);
  void BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node);
  void SetOnReceive(std::function<void(std::shared_ptr<NetMessage> msg, CNode*)>& func);

  void OnConnected(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& ec);
  void OnAccept(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<boost::asio::ip::tcp::acceptor> acc, const boost::system::error_code& ec);

private:
  void Shutdown();
  void WaitForShutdown();
  void ThreadSocketHandle();
  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisconnectNode(CNode* p_node);
  void OnDisconnect(std::shared_ptr<Peer> peer);
  bool OnReceiveNode(const char* p_buf, size_t len, CNode* p_node);
  void OnReceive(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer);
private:
  std::vector<boost::asio::ip::address_v4> GetLocalIPs();
  std::vector<boost::asio::ip::address_v4> LookupPublicIPs();
private:
  ambr::net::NetManagerConfig config_;
  std::list<Ptr_Unit> list_ptr_unit_;
  std::list<CNode*> list_in_nodes_;
  std::list<CNode*> list_out_nodes_;
  std::list<CNode*> list_in_nodes_wait_;
  std::list<CNode*> list_out_nodes_wait_;
  std::list<std::shared_ptr<Peer>> in_peers_;
  std::list<std::shared_ptr<Peer>> out_peers_;
  std::list<std::shared_ptr<Peer>> in_peers_wait_;
  std::list<std::shared_ptr<Peer>> out_peers_wait_;
  std::list<boost::asio::ip::tcp::endpoint> server_list_;
  std::shared_ptr<boost::asio::ip::tcp::acceptor> accept_;

  bool exit_;
  std::thread ios_thread_;
  boost::asio::io_service ios_;
  boost::threadpool::pool thread_pool_;

  Ptr_CScheduler p_scheduler;
  Ptr_PeerLogicValidation p_peerLogicValidation_;
  std::shared_ptr<store::StoreManager> store_manager_;

  std::function<void(std::shared_ptr<Peer>)> on_accept_func_;
  std::function<void(std::shared_ptr<Peer>)> on_connect_func_;
  std::function<void(std::shared_ptr<Peer>)> on_disconnect_func_;
  std::function<void(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer)> on_receive_func_;

  std::function<void(CNode*)> on_accept_node_func_;
  std::function<void(CNode*)> on_connect_node_func_;
  std::function<void(CNode*)> on_disconnect_node_func_;
  std::function<void(std::shared_ptr<NetMessage>,  CNode*)> on_receive_node_func_;
};

ambr::net::NetManager::Impl::Impl(std::shared_ptr<store::StoreManager> store_manager)
  : thread_pool_(std::thread::hardware_concurrency())
  , exit_(false)
  , store_manager_(store_manager)
  , p_scheduler(std::make_shared<CScheduler>())
  , CConnman(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())){
  /*std::vector<boost::asio::ip::address_v4> ips = LookupPublicIPs();
  if(ips.size()){
    server_list_.push_back(boost::asio::ip::tcp::endpoint(ips[0], config_.listen_port_));
  }*/
}

bool ambr::net::NetManager::Impl::init(const NetManagerConfig &config){
  std::vector<boost::asio::ip::address_v4> ips =  LookupPublicIPs();
  for(boost::asio::ip::address_v4 ip:ips){
    LOG(ERROR)<<ip.to_string();
  }
  config_ = std::move(config);
  //listen
  /*auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ios_);
  std::shared_ptr<boost::asio::ip::tcp::acceptor> acc = std::make_shared<boost::asio::ip::tcp::acceptor>(ios_, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), config.listen_port_));
  acc->async_accept(*socket,
                   boost::bind(&ambr::net::NetManager::Impl::OnAccept, this, socket, acc, boost::asio::placeholders::error)
                   );
  LOG(INFO)<<"start listen:"<<acc->local_endpoint().address().to_string()<<":"<<acc->local_endpoint().port();
  //connect
  for(boost::asio::ip::tcp::endpoint end_point:config.seed_list_){
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ios_);
    socket->async_connect(end_point, boost::bind(&ambr::net::NetManager::Impl::OnConnected, this, socket, boost::asio::placeholders::error));
  }
  ios_thread_ = std::thread(std::bind(&ambr::net::NetManager::Impl::ThreadSocketHandle, this));*/

  SetAcceptFunc(std::bind(&ambr::net::NetManager::Impl::OnAcceptNode, this, std::placeholders::_1));
  SetConnectFunc(std::bind(&ambr::net::NetManager::Impl::OnConnectNode, this, std::placeholders::_1));
  SetDisconnectFunc(std::bind(&ambr::net::NetManager::Impl::OnDisconnectNode, this, std::placeholders::_1));

  try{
    SelectParams(gArgs.GetChainName(), config.listen_port_);
  }
  catch(const std::exception& e) {
    LOG(INFO)<< "Error : " << e.what();
    return false;
  }
  p_peerLogicValidation_ = std::make_shared<PeerLogicValidation>(this, *p_scheduler, gArgs.GetBoolArg("-enablebip61", DEFAULT_ENABLE_BIP61));

  CConnman::Options connOptions;
  connOptions.nMaxConnections = MaxConnections;
  connOptions.nLocalServices = ServiceFlags(NODE_NETWORK | NODE_NETWORK_LIMITED);
  connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
  connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
  connOptions.m_msgproc = p_peerLogicValidation_.get();
  connOptions.m_added_nodes = gArgs.GetArgs("-addnode");

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

  std::vector<CAddress> vec_addrs;
  for(auto& it : config.vec_seed_){
    struct in_addr addr_;
    if(1 != inet_pton(AF_INET, it.str_ip_.c_str(), &addr_)){
      LOG(INFO) << "convert failed";
      return false;
    }
    CAddress addr(CService(addr_, it.port_), NODE_NONE);
    vec_addrs.push_back(addr);
  }

  AddNewAddresses(vec_addrs, CAddress());

  if(Start(*p_scheduler.get(), connOptions)){
    WaitForShutdown();
  }
  else{
    Interrupt();
  }
  Shutdown();
  return true;
}

void ambr::net::NetManager::Impl::SetOnReceive(std::function<void (std::shared_ptr<NetMessage>, std::shared_ptr<Peer>)> func){
  on_receive_func_ = func;
}

void ambr::net::NetManager::Impl::SendMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer){
  if(peer){
    peer->SendMessage(msg);
  }
}

void ambr::net::NetManager::Impl::BoardcastMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer){
  for(std::shared_ptr<Peer> peer_item:in_peers_){
    if(peer_item != peer){
      peer_item->SendMessage(msg);
    }
  }
  for(std::shared_ptr<Peer> peer_item:out_peers_){
    if(peer_item != peer){
      peer_item->SendMessage(msg);
    }
  }
}

void ambr::net::NetManager::Impl::SetOnDisconnect(std::function<void (std::shared_ptr<Peer>)> func){
  on_disconnect_func_ = func;
}

void ambr::net::NetManager::Impl::SetOnAccept(std::function<void (std::shared_ptr<Peer>)> func){
  on_accept_func_ = func;
}

void ambr::net::NetManager::Impl::SetOnConnected(std::function<void (std::shared_ptr<Peer>)> func){
  on_connect_func_ = func;
}

void ambr::net::NetManager::Impl::RemovePeer(std::shared_ptr<Peer> peer, uint32_t second){

  try{
    peer->socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
    peer->socket_->close();
  }catch(const boost::system::error_code& ec){

  }catch(...){

  }
  in_peers_.remove(peer);
  out_peers_.remove(peer);
  in_peers_wait_.remove(peer);
  out_peers_wait_.remove(peer);
}

void ambr::net::NetManager::Impl::RemoveNode(CNode* p_node, uint32_t second){
    p_node->CloseSocketDisconnect();
    std::vector<CNode*>& vec_nodes = GetVectorNodes();
    for(auto it = vec_nodes.begin(); it < vec_nodes.end(); ++it){
      if(p_node == *it){
        vec_nodes.erase(it);
      }
    }
}

void ambr::net::NetManager::Impl::SendMessage(CSerializedNetMsg&& msg, CNode* p_node){
  if(p_node){
    PushMessage(p_node, std::forward<CSerializedNetMsg>(msg));
  }
}

void ambr::net::NetManager::Impl::SetOnAccept(const std::function<void(CNode*)>& func){
 on_accept_node_func_ = func;
}

void ambr::net::NetManager::Impl::SetOnConnected(const std::function<void(CNode*)>& func){
  on_connect_node_func_ = func;
}

void ambr::net::NetManager::Impl::SetOnDisconnect(const std::function<void(CNode*)>& func){
  on_disconnect_node_func_ = func;
}

void ambr::net::NetManager::Impl::BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node){
  std::vector<CNode*>& vec_nodes = GetVectorNodes();
  for(auto it:vec_nodes){
    if(it != p_node){
      PushMessage(it, std::forward<CSerializedNetMsg>(msg));
    }
  }
}

void ambr::net::NetManager::Impl::SetOnReceive(std::function<void(std::shared_ptr<NetMessage> msg, CNode*)>& func){
  on_receive_node_func_ = func;
}

void ambr::net::NetManager::Impl::OnConnected(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code &ec){
  if(ec){
    LOG(WARNING)<<"connect error:"<<ec.message();
  }else{
    LOG(INFO)<<"connect success. from:"
            <<socket->remote_endpoint().address().to_string()<<":"<<socket->remote_endpoint().port()
            <<"To:"
            <<socket->local_endpoint().address().to_string()<<":"<<socket->local_endpoint().port();
    std::shared_ptr<Peer> peer = std::make_shared<Peer>(&ios_);
    peer->end_point_ = socket->remote_endpoint();
    peer->socket_ = socket;
    peer->connected_time_ = time(nullptr);
    peer->OnDisconnectFunc = std::bind(&ambr::net::NetManager::Impl::OnDisconnect, this, peer);
    peer->OnReceiveMessageFunc = std::bind(&ambr::net::NetManager::Impl::OnReceive, this, std::placeholders::_1, peer);
    peer->Start();
    out_peers_wait_.push_back(peer);
    if(on_connect_func_)on_connect_func_(peer);
    std::shared_ptr<NetMessage> net_msg = std::make_shared<NetMessage>();
    net_msg->version_ = 0x00000001;
    net_msg->len_ = 0;
    net_msg->command_ = MC_INVALIDATE;
    peer->SendMessage(net_msg);

  }
}

void ambr::net::NetManager::Impl::OnAccept(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<boost::asio::ip::tcp::acceptor> acc, const boost::system::error_code &ec){
  if(ec){
    LOG(WARNING)<<"accept error:"<<ec.message();
  }else{
    LOG(INFO)<<"receive a connection. from:"
            <<socket->remote_endpoint().address().to_string()<<":"<<socket->remote_endpoint().port()
            <<"To:"
            <<socket->local_endpoint().address().to_string()<<":"<<socket->local_endpoint().port();
    std::shared_ptr<Peer> peer = std::make_shared<Peer>(&ios_);
    peer->end_point_ = socket->remote_endpoint();
    peer->socket_ = socket;
    peer->connected_time_ = time(nullptr);
    peer->OnDisconnectFunc = std::bind(&ambr::net::NetManager::Impl::OnDisconnect, this, peer);
    peer->OnReceiveMessageFunc = std::bind(&ambr::net::NetManager::Impl::OnReceive, this, std::placeholders::_1, peer);
    peer->Start();
    in_peers_wait_.push_back(peer);
    if(on_accept_func_)on_accept_func_(peer);
    std::shared_ptr<NetMessage> net_msg = std::make_shared<NetMessage>();
    net_msg->version_ = 0x00000001;
    net_msg->len_ = 0;
    net_msg->command_ = MC_INVALIDATE;
    peer->SendMessage(net_msg);

  }
  if(exit_)return;
  std::shared_ptr<boost::asio::ip::tcp::socket> socket_new = std::make_shared<boost::asio::ip::tcp::socket>(ios_);
  acc->async_accept(*socket_new,
                   boost::bind(&ambr::net::NetManager::Impl::OnAccept, this, socket_new, acc, boost::asio::placeholders::error)
                    );
}

void ambr::net::NetManager::Impl::Shutdown(){
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    Stop();
}

void ambr::net::NetManager::Impl::WaitForShutdown(){
    while (!ShutdownRequested())
    {
        MilliSleep(200);
    }
    Interrupt();
}

void ambr::net::NetManager::Impl::ThreadSocketHandle(){
  ios_.run();
}

void ambr::net::NetManager::Impl::OnAcceptNode(CNode* p_node){
  if(on_accept_node_func_){
    on_accept_node_func_(p_node);
  }
}

void ambr::net::NetManager::Impl::OnConnectNode(CNode* p_node){
  if(on_connect_node_func_){
    on_connect_node_func_(p_node);
  }
}

void ambr::net::NetManager::Impl::OnDisconnectNode(CNode* p_node){
    if(on_disconnect_node_func_){
      on_disconnect_node_func_(p_node);
    }
}

void ambr::net::NetManager::Impl::OnDisconnect(std::shared_ptr<Peer> peer){
  LOG(WARNING)<<"peer disconnect:"<<peer->end_point_.address().to_string()<<":"<<peer->end_point_.port();
  RemovePeer(peer, 0);
  if(on_disconnect_func_)on_disconnect_func_(peer);
}

bool ambr::net::NetManager::Impl::OnReceiveNode(const char* p_buf, size_t len, CNode* p_node){
    CNetMessage netmsg(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION);

    while(len > 0){
      int pos;
      if(false == netmsg.in_data){
        pos = netmsg.readHeader(p_buf, len);
      }
      else{
        pos = netmsg.readData(++p_buf, len);
      }

      if (pos < 0){
        return true;
      }

      if(netmsg.in_data && netmsg.hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH){
        LOG(INFO) << "Oversized message from node = " << p_node->GetAddrName() << ", disconnecting";
        return true;
      }

      p_buf += pos;
      len -= pos;
      if(netmsg.complete()){
        break;
      }
    }

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

        if(is_wait){
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

        if(is_wait){
          return false;
        }
        for(auto& it : list_in_nodes_){
          if(it == p_node){
            RemoveNode(p_node, 0);
            return true;
          }
        }

        for(auto& it : list_out_nodes_){
          if(it == p_node){
            RemoveNode(p_node, 0);
            return true;
          }
        }
      }
    }
    else if(NetMsgType::ADDR == tmp){

    }
    else if(NetMsgType::UNIT == tmp){
      std::vector<uint8_t> buf;
      buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());
      Ptr_Unit unit = ambr::core::Unit::CreateUnitByByte(buf);
      if(unit){
        if(!unit->prev_unit().is_zero() && nullptr == store_manager_->GetUnit(unit->prev_unit()) && nullptr == store_manager_->GetValidateUnit(unit->prev_unit())){
          ambr::core::UnitHash hash;
          LOG(INFO) << "No last unit:" << unit->SerializeJson();
          if(ambr::core::UnitType::Validator == unit->type()){
            store_manager_->GetLastValidateUnit(hash);
          }
          else{
            store_manager_->GetLastUnitHashByPubKey(unit->public_key(), hash);
          }
          std::string str_data = hash.encode_to_hex() + ":" + unit->hash().encode_to_hex();
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::SECTION, str_data), p_node);
        }
        else if(ambr::core::UnitType::send == unit->type()){
          LOG(INFO) << "Get send unit:" << unit->SerializeJson();
          std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
          if(send_unit && store_manager_->AddSendUnit(send_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::receive == unit->type()){
          LOG(INFO) << "Get receive unit:" << unit->SerializeJson();
          std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
          if(receive_unit && store_manager_->AddReceiveUnit(receive_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::Vote == unit->type()){
          LOG(INFO) << "Get vote unit:" << unit->SerializeJson();
          std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(unit);
          if(vote_unit && store_manager_->AddVote(vote_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::Validator == unit->type()){
          LOG(INFO) << "Get validator unit:" << unit->SerializeJson();
          std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(unit);

          if(validator_unit){
            ambr::core::UnitHash newest_unithash;
            std::shared_ptr<ambr::core::Unit> ptr_unit = nullptr;
            const ambr::core::UnitHash& last_unithash = validator_unit->prev_unit();

            if(store_manager_->GetLastValidateUnit(newest_unithash)){
              while(last_unithash != newest_unithash){
                std::shared_ptr<ambr::store::UnitStore>&& ptr_unitstore = store_manager_->GetUnit(newest_unithash);
                if(ptr_unitstore){
                  ptr_unit = ptr_unitstore->GetUnit();
                  if(ptr_unit){
                    newest_unithash = ptr_unit->prev_unit();
                  }
                  else{
                    break;
                  }
                }
                else{
                  break;
                }
              }
            }

            if(last_unithash == newest_unithash){
              if(nullptr == ptr_unit || ptr_unit && FixedRate <= validator_unit->percent()){
                if(store_manager_->AddValidateUnit(validator_unit, nullptr)){
                  BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
                }
              }
            }
            else{
              if(store_manager_->AddValidateUnit(validator_unit, nullptr)){
                BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
              }
            }
          }
        }
        else if(ambr::core::UnitType::EnterValidateSet == unit->type()){
          LOG(INFO) << "Get enter validator unit:" << unit->SerializeJson();
          std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(unit);
          if(enter_validator_unit && store_manager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
        else if(ambr::core::UnitType::LeaveValidateSet == unit->type()){
          LOG(INFO) << "Get leave validator unit:" << unit->SerializeJson();
          std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(unit);
          if(leave_validator_unit && store_manager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr)){
            BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, buf), p_node);
          }
        }
      }
    }
    else if(NetMsgType::SECTION == tmp){
      std::string strTmp;
      strTmp.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());
      LOG(INFO)<<"Get New Section:"<< strTmp;
      ambr::core::UnitHash firsthash, lasthash;
      size_t num_pos = strTmp.find(':');
      if(num_pos != std::string::npos){
        firsthash.decode_from_hex(strTmp.substr(0, num_pos));
        lasthash.decode_from_hex(strTmp.substr(num_pos + 1, 64));

        std::list<Ptr_Unit> list_p_unit;
        while(firsthash != lasthash){
          Ptr_UnitStore p_unitstore = store_manager_->GetUnit(lasthash);

          Ptr_Unit p_unit;
          if(p_unitstore){
            p_unit = p_unitstore->GetUnit();
          }
          else{
            p_unit = store_manager_->GetValidateUnit(lasthash);
          }

          if(p_unit){
              list_p_unit.push_front(p_unit);
          }
          else{
              break;
          }

          Ptr_UnitStore p_prevunitstore = store_manager_->GetUnit(p_unit->prev_unit());

          Ptr_Unit p_prevunit;
          if(p_prevunitstore){
            p_prevunit = p_prevunitstore->GetUnit();
          }
          else{
            p_prevunit = store_manager_->GetValidateUnit(p_unit->prev_unit());
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
          BoardcastMessage(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::UNIT, str_data), p_node);
        }
      }
    }
    else if(NetMsgType::SECTIONUNIT == tmp){
        std::vector<uint8_t> buf;
        buf.assign(netmsg.vRecv.begin(), netmsg.vRecv.end());
        Ptr_Unit unit = ambr::core::Unit::CreateUnitByByte(buf);
        if(unit){
          switch (unit->type()) {
          case ambr::core::UnitType::send:
          {
            LOG(INFO)<<"Get send section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
            store_manager_->AddSendUnit(send_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::receive:
          {
              LOG(INFO)<<"Get receive section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
              store_manager_->AddReceiveUnit(receive_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::Vote:
          {
              LOG(INFO)<<"Get vote section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(unit);
              store_manager_->AddVote(vote_unit, nullptr);
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

                  if(store_manager_->GetLastValidateUnit(newest_unithash)){
                    while(last_unithash != newest_unithash){
                      std::shared_ptr<ambr::store::UnitStore>&& ptr_unitstore = store_manager_->GetUnit(newest_unithash);
                      if(ptr_unitstore){
                          ptr_unit = ptr_unitstore->GetUnit();
                          if(ptr_unit){
                            newest_unithash = ptr_unit->prev_unit();
                          }
                          else{
                            break;
                          }
                      }
                      else{
                        break;
                      }
                    }
                  }

                  if(last_unithash == newest_unithash){
                    if(nullptr == ptr_unit || ptr_unit && FixedRate <= validator_unit->percent()){
                      store_manager_->AddValidateUnit(validator_unit, nullptr);
                    }
                  }
                  else{
                    store_manager_->AddValidateUnit(validator_unit, nullptr);
                  }
              }
          }
          break;
          case ambr::core::UnitType::EnterValidateSet:
          {
              LOG(INFO)<<"Get enter validator section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(unit);
              store_manager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr);
          }
          break;
          case ambr::core::UnitType::LeaveValidateSet:
          {
              LOG(INFO)<<"Get leave validator section unit:"<<unit->SerializeJson();
              std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(unit);
              store_manager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr);
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

void ambr::net::NetManager::Impl::OnReceive(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer){
  if(MC_INVALIDATE == msg->command_){
    if(msg->version_ != 0x00000001){
      LOG(WARNING)<<"Error peer version:"<<std::hex<<std::setw(8)<<std::setfill('0')<<msg->version_
                 <<"in"<<peer->end_point_.address().to_string()<<":"<<std::dec<<std::setw(0)<<peer->end_point_.port();
      RemovePeer(peer, 0);
      in_peers_.remove(peer);
      out_peers_.remove(peer);
      in_peers_wait_.remove(peer);
      out_peers_wait_.remove(peer);
    }else{
      bool is_wait = false;
      for(std::shared_ptr<Peer> item:in_peers_wait_){
        if(item == peer){
          is_wait = true;
          in_peers_wait_.remove(peer);
          in_peers_.push_back(peer);
          LOG(INFO)<<"Right peer version:"<<std::hex<<std::setw(8)<<std::setfill('0')<<msg->version_
                     <<"save"<<peer->end_point_.address().to_string()<<":"<<std::dec<<std::setw(0)<<peer->end_point_.port()
                    <<"to in_peers";
          break;
        }
      }

      if(is_wait)return;
      for(std::shared_ptr<Peer> item:out_peers_wait_){
        if(item == peer){
          is_wait = true;
          out_peers_wait_.remove(peer);
          out_peers_.push_back(peer);
          LOG(INFO)<<"Right peer version:"<<std::hex<<std::setw(8)<<std::setfill('0')<<msg->version_
                     <<"save"<<peer->end_point_.address().to_string()<<":"<<std::dec<<std::setw(0)<<peer->end_point_.port()
                    <<"to out_peers";
          //Send addr msg
          std::vector<boost::asio::ip::address_v4> addrs = LookupPublicIPs();
          if(addrs.size()){
            NetMessageAddr addr_msg;
            addr_msg.addr_list_.push_back(std::pair<boost::asio::ip::address_v4, uint16_t>(addrs[0], config_.listen_port_));
            std::shared_ptr<NetMessage> msg = std::make_shared<NetMessage>();
            msg->version_ = 0x00000001;
            msg->command_ = MC_ADDR;
            msg->str_msg_ = addr_msg.EncodeToString();
            msg->len_ = msg->str_msg_.size();
            server_list_.push_back(peer->end_point_);
            peer->SendMessage(msg);
            break;
          }
        }
      }

      if(is_wait)return;
      for(std::shared_ptr<Peer> item:in_peers_){
        if(item == peer){
          //Get message at error time
          RemovePeer(peer, 0);
          return;
        }
      }

      for(std::shared_ptr<Peer> item:out_peers_){
        if(item == peer){
          //Get message at error time
          RemovePeer(peer, 0);
          return;
        }
      }
    }

  }else if(MC_ADDR == msg->command_){
    //uint16_t server_count =
    NetMessageAddr addr_msg;
    if(addr_msg.DecodeFromString(msg->str_msg_)){
      LOG(INFO)<<"Receive addr msg";
      if(addr_msg.addr_list_.size() == 1){//boardcast
        boost::asio::ip::tcp::endpoint msg_end_point(addr_msg.addr_list_.front().first, addr_msg.addr_list_.front().second);
        LOG(INFO)<<"Decode addr msg "<<msg_end_point.address().to_string()<<":"<<msg_end_point.port();
        bool finded = false;
        for(boost::asio::ip::tcp::endpoint end_point:server_list_){
          if(end_point == msg_end_point){
            finded = true;
            break;
          }
        }
        if(finded == false){//not find server,boardcast
          server_list_.push_back(msg_end_point);
          LOG(INFO)<<"boardcast addr msg";
          BoardcastMessage(msg, peer);
          {
            /*auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ios_);
            socket->async_connect(msg_end_point, boost::bind(&ambr::net::NetManager::Impl::OnConnected, this, socket, boost::asio::placeholders::error));*/
          }
        }
      }
    }else{
      //TODO
    }
  }
  else if(MC_NEW_UNIT == msg->command_){
    std::vector<uint8_t> buf;
    buf.assign(msg->str_msg_.begin(), msg->str_msg_.end());
    Ptr_Unit unit = ambr::core::Unit::CreateUnitByByte(buf);
    if(unit){
      if(!unit->prev_unit().is_zero() && nullptr == store_manager_->GetUnit(unit->prev_unit()) && nullptr == store_manager_->GetValidateUnit(unit->prev_unit())){
        ambr::core::UnitHash hash;
        LOG(INFO)<<"No last unit:"<<unit->SerializeJson();
        if(ambr::core::UnitType::Validator == unit->type()){
          store_manager_->GetLastValidateUnit(hash);
        }
        else{
          store_manager_->GetLastUnitHashByPubKey(unit->public_key(), hash);
        }
        auto ptr_msg = std::make_shared<NetMessage>();
        ptr_msg->version_ = 0x00000001;
        ptr_msg->command_ = MC_NEW_SECTION;
        ptr_msg->str_msg_ = hash.encode_to_hex() + ":" + unit->hash().encode_to_hex();
        ptr_msg->len_ = ptr_msg->str_msg_.size();
        BoardcastMessage(ptr_msg, peer);
      }
      else if(unit->type() == ambr::core::UnitType::send){
        LOG(INFO)<<"Get send unit:"<<unit->SerializeJson();
        std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
        if(send_unit && store_manager_->AddSendUnit(send_unit, nullptr)){
          BoardcastMessage(msg, peer);
        }
      }
      else if(ambr::core::UnitType::receive == unit->type()){
        LOG(INFO)<<"Get receive unit:"<<unit->SerializeJson();
        std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
        if(receive_unit && store_manager_->AddReceiveUnit(receive_unit, nullptr)){
          BoardcastMessage(msg, peer);
        }
      }
      else if(ambr::core::UnitType::Vote == unit->type()){
        LOG(INFO)<<"Get receive unit:"<<unit->SerializeJson();
        std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(unit);
        if(vote_unit && store_manager_->AddVote(vote_unit, nullptr)){
          BoardcastMessage(msg, peer);
        }
      }
      else if(ambr::core::UnitType::Validator == unit->type()){
        LOG(INFO)<<"Get validator unit:"<<unit->SerializeJson();
        std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(unit);
        if(validator_unit && store_manager_->AddValidateUnit(validator_unit, nullptr)){
          BoardcastMessage(msg, peer);
        }
      }
      else if(ambr::core::UnitType::EnterValidateSet == unit->type()){
        LOG(INFO)<<"Get enter validator unit:"<<unit->SerializeJson();
        std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(unit);
        if(enter_validator_unit && store_manager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr)){
          BoardcastMessage(msg, peer);
        }
      }
      else if(ambr::core::UnitType::LeaveValidateSet == unit->type()){
        LOG(INFO)<<"Get leave validator unit:"<<unit->SerializeJson();
        std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(unit);
        if(leave_validator_unit && store_manager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr)){
          BoardcastMessage(msg, peer);
        }
      }
    }
  }
  else if(MC_NEW_SECTION == msg->command_){
    LOG(INFO)<<"Get New Section:"<< msg->str_msg_;
    ambr::core::UnitHash firsthash, lasthash;
    size_t num_pos = msg->str_msg_.find(':');
    if(num_pos != std::string::npos){
      firsthash.decode_from_hex(msg->str_msg_.substr(0, num_pos));
      lasthash.decode_from_hex(msg->str_msg_.substr(num_pos + 1, 64));

      std::list<Ptr_Unit> list_p_unit;
      while(firsthash != lasthash){
        Ptr_UnitStore p_unitstore = store_manager_->GetUnit(lasthash);

        Ptr_Unit p_unit;
        if(p_unitstore){
          p_unit = p_unitstore->GetUnit();
        }
        else{
          p_unit = store_manager_->GetValidateUnit(lasthash);
        }

        if(p_unit){
            list_p_unit.push_front(p_unit);
        }
        else{
            break;
        }

        Ptr_UnitStore p_prevunitstore = store_manager_->GetUnit(p_unit->prev_unit());

        Ptr_Unit p_prevunit;
        if(p_prevunitstore){
          p_prevunit = p_prevunitstore->GetUnit();
        }
        else{
          p_prevunit = store_manager_->GetValidateUnit(p_unit->prev_unit());
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
        auto ptr_msg = std::make_shared<NetMessage>();

        ptr_msg->version_ = 0x00000001;
        ptr_msg->command_ = MC_NEW_SECTION_UNIT;
        ptr_msg->str_msg_.assign(buf.begin(), buf.end());
        ptr_msg->len_ = ptr_msg->str_msg_.size();
        BoardcastMessage(ptr_msg, peer);
      }
    }
  }
  else if(MC_NEW_SECTION_UNIT == msg->command_){
      std::vector<uint8_t> buf;
      buf.assign(msg->str_msg_.begin(), msg->str_msg_.end());
      Ptr_Unit unit = ambr::core::Unit::CreateUnitByByte(buf);
      if(unit){
        switch (unit->type()) {
        case ambr::core::UnitType::send:
        {
          LOG(INFO)<<"Get send section unit:"<<unit->SerializeJson();
          std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
          if(send_unit && store_manager_->AddSendUnit(send_unit, nullptr)){
            //BoardcastMessage(msg, peer);
          }
        }
        break;
        case ambr::core::UnitType::receive:
        {
            LOG(INFO)<<"Get receive section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
            if(receive_unit && store_manager_->AddReceiveUnit(receive_unit, nullptr)){
              //BoardcastMessage(msg, peer);
            }
        }
        break;
        case ambr::core::UnitType::Vote:
        {
            LOG(INFO)<<"Get vote section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::VoteUnit> vote_unit = std::dynamic_pointer_cast<ambr::core::VoteUnit>(unit);
            if(vote_unit && store_manager_->AddVote(vote_unit, nullptr)){
              //BoardcastMessage(msg, peer);
            }
        }
        break;
        case ambr::core::UnitType::Validator:
        {
            LOG(INFO)<<"Get validator section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::ValidatorUnit> validator_unit = std::dynamic_pointer_cast<ambr::core::ValidatorUnit>(unit);
            if(validator_unit && store_manager_->AddValidateUnit(validator_unit, nullptr)){
              //BoardcastMessage(msg, peer);
            }
        }
        break;
        case ambr::core::UnitType::EnterValidateSet:
        {
            LOG(INFO)<<"Get enter validator section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::EnterValidateSetUint> enter_validator_unit = std::dynamic_pointer_cast<ambr::core::EnterValidateSetUint>(unit);
            if(enter_validator_unit && store_manager_->AddEnterValidatorSetUnit(enter_validator_unit, nullptr)){
              //BoardcastMessage(msg, peer);
            }
        }
        break;
        case ambr::core::UnitType::LeaveValidateSet:
        {
            LOG(INFO)<<"Get leave validator section unit:"<<unit->SerializeJson();
            std::shared_ptr<ambr::core::LeaveValidateSetUint> leave_validator_unit = std::dynamic_pointer_cast<ambr::core::LeaveValidateSetUint>(unit);
            if(leave_validator_unit && store_manager_->AddLeaveValidatorSetUnit(leave_validator_unit, nullptr)){
              //BoardcastMessage(msg, peer);
            }
        }
        break;
        default:
        break;
        }
      }
  }
  else{
    thread_pool_.schedule(boost::bind(on_receive_func_, msg, peer));
  }
}

std::vector<boost::asio::ip::address_v4> ambr::net::NetManager::Impl::GetLocalIPs(){
  std::vector<boost::asio::ip::address_v4> rtn;
  int sock_fd;
  struct ifconf conf;
  struct ifreq *ifr;
  char buff[sizeof(struct ifreq)*20] = {0};
  int num;
  int i;

  sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
  if ( sock_fd < 0 )
    return rtn;

  conf.ifc_len = sizeof(struct ifreq)*20;
  conf.ifc_buf = buff;

  if(ioctl(sock_fd, SIOCGIFCONF, &conf) < 0){
    close(sock_fd);
    return rtn;
  }
  num = conf.ifc_len / sizeof(struct ifreq);
  ifr = conf.ifc_req;
  for(i = 0; i < num; i++){
    struct sockaddr_in *sin = (struct sockaddr_in *)(&ifr->ifr_addr);
    if (ioctl(sock_fd, SIOCGIFFLAGS, ifr) < 0){
      close(sock_fd);
      return rtn;
    }
    if ((ifr->ifr_flags & IFF_UP)){
      rtn.push_back(boost::asio::ip::address_v4::from_string(inet_ntoa(sin->sin_addr)));
    }
    ifr++;
  }
  close(sock_fd);
  return rtn;
}

std::vector<boost::asio::ip::address_v4> ambr::net::NetManager::Impl::LookupPublicIPs(){
  std::vector<boost::asio::ip::address_v4> all_ip = GetLocalIPs();
  std::vector<boost::asio::ip::address_v4> public_ip;
  for(boost::asio::ip::address_v4 ip:all_ip){
    if(ip.to_bytes().at(0) != (uint8_t)127){
      public_ip.push_back(ip);
    }
  }
  return public_ip;
}

ambr::net::NetManager::NetManager(std::shared_ptr<store::StoreManager> store_mananger){
  impl_ = new Impl(store_mananger);
}

bool ambr::net::NetManager::init(const ambr::net::NetManagerConfig &config){
  return impl_->init(config);
}

void ambr::net::NetManager::RemovePeer(CNode* p_node, uint32_t second){
  impl_->RemoveNode(p_node, second);
}

void ambr::net::NetManager::BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node){
  impl_->BoardcastMessage(std::forward<CSerializedNetMsg>(msg), p_node);
}

void ambr::net::NetManager::SetOnAcceptNode(const std::function<void(CNode*)>& func){
  impl_->SetOnAccept(func);
}

void ambr::net::NetManager::SetOnConnectedNode(const std::function<void(CNode*)>& func){
  impl_->SetOnConnected(func);
}

void ambr::net::NetManager::SetOnDisconnectNode(const std::function<void(CNode*)>& func){
  impl_->SetOnDisconnect(func);
}

void ambr::net::Peer::Start(){
  std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
  buf->resize(NetMessage::HEAD_SIZE);
  boost::asio::async_read(
        *socket_,
        boost::asio::buffer(&((*buf)[0]), buf->size()), boost::bind(&ambr::net::Peer::OnReceiveMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error)
      );
}

void ambr::net::Peer::SendMessage(std::shared_ptr<ambr::net::NetMessage> msg){
  msg_list_for_send_.push_back(msg);
  if(!sending_){
    std::shared_ptr<ambr::net::NetMessage> msg = msg_list_for_send_.front();
    msg_list_for_send_.pop_front();
    std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
    buf->resize(msg->HEAD_SIZE + msg->str_msg_.size());
    memcpy(&((*buf)[0]), &(*msg), msg->HEAD_SIZE);
    memcpy(&((*buf)[msg->HEAD_SIZE]), msg->str_msg_.data(), msg->str_msg_.size());
    boost::asio::async_write(*socket_, boost::asio::buffer(*buf), boost::bind(&ambr::net::Peer::OnSendMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));
  }
}

void ambr::net::Peer::OnReceiveMessage(std::shared_ptr<std::vector<uint8_t> > buf_receved, size_t translated, const boost::system::error_code &ec){
  if(ec){
    LOG(WARNING)<<"Receive error:"<<ec.message()<<" at "<<end_point_.address().to_string()<<":"<<end_point_.port();
    OnDisconnectFunc(ec);
  }else{
    buf_.insert(buf_.end(), buf_receved->data(),buf_receved->data()+translated);
    if(buf_.size() < NetMessage::HEAD_SIZE){
      std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
      buf->resize(NetMessage::HEAD_SIZE-buf_.size());
      boost::asio::async_read(
            *socket_,
            boost::asio::buffer(&((*buf)[0]), buf->size()),
            boost::bind(&ambr::net::Peer::OnReceiveMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error)
          );
    }else if(buf_.size() >= NetMessage::HEAD_SIZE){
      uint32_t len = *((uint32_t*)&buf_[4]);
      if(buf_.size() == NetMessage::HEAD_SIZE+len){//all message receive complete
        std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
        buf->resize(NetMessage::HEAD_SIZE);
        boost::asio::async_read(
              *socket_,
              boost::asio::buffer(&((*buf)[0]), buf->size()),
              boost::bind(&ambr::net::Peer::OnReceiveMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error)
            );
        std::shared_ptr<NetMessage> msg = std::shared_ptr<NetMessage>(new NetMessage());
        msg->version_ = *((uint32_t*)&buf_[0]);
        msg->len_ = *((uint32_t*)&buf_[4]);
        msg->command_ = *((uint32_t*)&buf_[8]);
        msg->str_msg_.assign(&buf_[NetMessage::HEAD_SIZE], &buf_[NetMessage::HEAD_SIZE+msg->len_]);
        OnReceiveMessageFunc(msg);
        buf_.clear();
      }else{
        std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
        buf->resize(NetMessage::HEAD_SIZE+len - buf_.size());
        boost::asio::async_read(
              *socket_,
              boost::asio::buffer(&((*buf)[0]), buf->size()),
              boost::bind(&ambr::net::Peer::OnReceiveMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error)
            );
      }
    }
  }
}

void ambr::net::Peer::OnSendMessage(std::shared_ptr<std::vector<uint8_t> > buf, size_t translated, const boost::system::error_code &ec){
  buf->erase(buf->begin(), buf->begin()+translated);
  if(buf->size()){
    boost::asio::async_write(*socket_, boost::asio::buffer(*buf),
                           boost::bind(&ambr::net::Peer::OnSendMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));
  }else{
    if(msg_list_for_send_.size()){
      std::shared_ptr<ambr::net::NetMessage> msg = msg_list_for_send_.front();
      msg_list_for_send_.pop_front();
      std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
      buf->resize(msg->HEAD_SIZE + msg->str_msg_.size());
      memcpy(&((*buf)[0]), &(*msg), msg->HEAD_SIZE);
      memcpy(&((*buf)[msg->HEAD_SIZE]), msg->str_msg_.data(), msg->str_msg_.size());
      boost::asio::async_write(*socket_, boost::asio::buffer(*buf),
                               boost::bind(&ambr::net::Peer::OnSendMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));
    }else{
      sending_ = false;
    }
  }
}
