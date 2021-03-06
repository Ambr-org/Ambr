#ifndef _AMBR_SYN_MANAGER_H_
#define _AMBR_SYN_MANAGER_H_

#include "net.h"
#include "core/unit.h"
#include "scheduler.h"
#include "chainparams.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "store/store_manager.h"

#include <time.h>
#include <atomic>
#include <list>
#include <iostream>
#include <memory.h>
#include <functional>
#include <boost/asio.hpp>
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




class SynManager{
public:
  SynManager(Ptr_StoreManager p_storemanager);

  void OnAcceptNode(CNode* p_node);
  void OnConnectNode(CNode* p_node);
  void OnDisConnectNode(CNode* p_node);
  bool Init(const SynManagerConfig& config);
  void RemoveNode(CNode* p_node, uint32_t second);
  bool OnReceiveNode(const CNetMessage& netmsg, CNode* p_node);
  void SetOnAcceptNode(const std::function<void(CNode*)>& func);
  void SetOnConnectedNode(const std::function<void(CNode*)>& func);
  void SetOnDisconnectNode(const std::function<void(CNode*)>& func);

  void BoardCastNewUnit(std::shared_ptr<core::Unit> p_unit);
  bool GetNodeIfPauseSend(const std::string& node_addr);
  bool GetNodeIfPauseReceive(const std::string& node_addr);
  uint64_t GetNodeNonce(const std::string& node_addr);
public:
  class Impl;
private:
  Impl* p_impl_;
  std::mutex state_mutex_;
  Ptr_StoreManager p_storemanager_;
};
}
}
#pragma pack()
#endif
