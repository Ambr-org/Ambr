#ifndef _AMBR_SYN_MANAGER_H_
#define _AMBR_SYN_MANAGER_H_

#include "net.h"
#include "core/unit.h"
#include "scheduler.h"
#include "chainparams.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "store/store_manager.h"

#include <boost/asio.hpp>
#include <time.h>
#include <atomic>
#include <list>
#include <memory.h>
#include <functional>
#include <boost/threadpool.hpp>

#pragma pack(1)

using Ptr_CConnman = std::shared_ptr<CConnman>;
using Ptr_Unit = std::shared_ptr<ambr::core::Unit>;
using Ptr_CScheduler = std::shared_ptr<CScheduler>;
using Ptr_UnitStore = std::shared_ptr<ambr::store::UnitStore>;
using Ptr_StoreManager = std::shared_ptr<ambr::store::StoreManager>;
using Ptr_PeerLogicValidation = std::shared_ptr<PeerLogicValidation>;

namespace ambr{
namespace store{
  class StoreManager;
}

namespace syn{

struct NetMessage{
  uint32_t len_;
  uint32_t version_;
  uint32_t command_;
  std::string str_msg_;
  static const uint32_t HEAD_SIZE = 12;
};

struct SynManagerConfig{
  uint32_t max_in_peer_;
  uint32_t max_out_peer_;
  uint32_t max_in_peer_for_optimize_;
  uint32_t max_out_peer_for_optimize_;
  uint32_t heart_time_;
  uint16_t listen_port_;
  bool use_upnp_;
  bool use_natp_;
  bool use_nat_pmp_;
  std::vector<std::string> vec_seed_;
};

class SynState{
public:
  bool is_sync_ = false;
  bool is_online_ = false;
};

class Impl{
public:
  Impl(Ptr_StoreManager p_store_manager);

  void RequestValidator();
  uint32_t GetNodeCount();
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

  void ReturnDynastyNo(CNode* p_node);
  void ReceiveUnit(const Ptr_Unit& p_unit, CNode* p_node);
  void ReceiveDynastyNo(const uint64_t& num, CNode* p_node);
  bool ReceiveValidatorUnit(const Ptr_Unit& p_unit, CNode* p_node);
  void ReceiveDynasty(const std::vector<uint8_t>& buf, CNode* p_node);
  void ReceiveNoValidatorUnit(const std::string& strTmp, CNode* p_node);
  void ReturnValidatorUnit(const std::vector<uint8_t>& buf, CNode* p_node);

private:
  void Shutdown();
  void WaitForShutdown();
  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisConnectNode(CNode* p_node);

private:
  bool exit_;
  uint64_t num_val_no_;
  uint64_t num_node_no_;
  CNode* p_max_no_node_;
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

class SynManager{
public:
  SynManager(Ptr_StoreManager p_storemanager);

  bool Init(const SynManagerConfig& config);
  void RemoveNode(CNode* p_node, uint32_t second);
  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node);
  void SetOnAcceptNode(const std::function<void(CNode*)>& func);
  void SetOnConnectedNode(const std::function<void(CNode*)>& func);
  void SetOnDisconnectNode(const std::function<void(CNode*)>& func);

  void BoardCastNewSendUnit(std::shared_ptr<core::SendUnit> p_unit);
  void BoardCastNewReceiveUnit(std::shared_ptr<core::ReceiveUnit> p_unit);
  void BoardCastNewValidatorUnit(std::shared_ptr<core::ValidatorUnit> p_unit);
  void BoardCastNewJoinValidatorSetUnit(std::shared_ptr<core::EnterValidateSetUint> p_unit);
  void BoardCastNewLeaveValidatorSetUnit(std::shared_ptr<core::LeaveValidateSetUint> p_unit);
  void BoardCastNewVoteUnit(std::shared_ptr<core::VoteUnit> p_unit);

  bool GetNodeIfPauseSend(const std::string& node_addr);
  bool GetNodeIfPauseReceive(const std::string& node_addr);

private:
  Impl* p_impl_;
  std::mutex state_mutex_;
  Ptr_StoreManager p_storemanager_;
};
}
}
#pragma pack()
#endif
