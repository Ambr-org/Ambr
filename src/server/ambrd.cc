
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Written by kan                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <string>
#include <platform.h>
#include "ambrd.h"
#include "server_interface.h"
#include <p2p/net.h>
#include <p2p/utiltime.h>
#include <p2p/shutdown.h>
#include <p2p/net_processing.h>
#include <p2p/init.h>
#include <glog/logging.h>
#include <boost/format.hpp>
#include "store/store_manager.h"
#include "synchronization/syn_manager.h"
#include "rpc/rpc_server.h"

std::unique_ptr<ambr::rpc::RpcServer> p_rpc;
std::shared_ptr<ambr::store::StoreManager> p_store_manager;
std::shared_ptr<ambr::syn::SynManager> p_syn_manager;

namespace ambr {
namespace server {
int DoServer(const std::string& db_path, uint16_t rpc_port, uint16_t p2p_port, const std::string& seed_ip, uint16_t seed_port) {
  p_store_manager = std::make_shared<ambr::store::StoreManager>();
  p_syn_manager = std::make_shared<ambr::syn::SynManager>(p_store_manager);
  p_rpc = std::unique_ptr<ambr::rpc::RpcServer>(new ambr::rpc::RpcServer());

  p_store_manager->Init(db_path);
  google::SetLogDestination(google::GLOG_INFO, (db_path+"/log.log").c_str());
  p_store_manager->AddCallBackReceiveNewSendUnit(std::bind(&ambr::syn::SynManager::BoardCastNewSendUnit, p_syn_manager.get(), std::placeholders::_1));
  p_store_manager->AddCallBackReceiveNewReceiveUnit(std::bind(&ambr::syn::SynManager::BoardCastNewReceiveUnit, p_syn_manager.get(), std::placeholders::_1));
  p_store_manager->AddCallBackReceiveNewValidatorUnit(std::bind(&ambr::syn::SynManager::BoardCastNewValidatorUnit, p_syn_manager.get(), std::placeholders::_1));
  p_store_manager->AddCallBackReceiveNewJoinValidatorSetUnit(std::bind(&ambr::syn::SynManager::BoardCastNewJoinValidatorSetUnit, p_syn_manager.get(), std::placeholders::_1));
  p_store_manager->AddCallBackReceiveNewLeaveValidatorSetUnit(std::bind(&ambr::syn::SynManager::BoardCastNewLeaveValidatorSetUnit, p_syn_manager.get(), std::placeholders::_1));
  p_store_manager->AddCallBackReceiveNewVoteUnit(std::bind(&ambr::syn::SynManager::BoardCastNewVoteUnit, p_syn_manager.get(), std::placeholders::_1));

  p_rpc->StartRpcServer(p_store_manager, rpc_port);

  ambr::syn::SynManagerConfig config;
  config.max_in_peer_ = 8;
  config.max_out_peer_ = 8;
  config.max_in_peer_for_optimize_ = 8;
  config.max_out_peer_for_optimize_ = 8;
  config.listen_port_ = p2p_port;

  config.use_upnp_ = false;
  config.use_nat_pmp_ = false;
  config.use_natp_ = false;
  config.heart_time_ = 88;

  config.vec_seed_.push_back((boost::format("%s:%d")%seed_ip%seed_port).str());

  CConnman::Options connOptions;
  connOptions.nMaxConnections = 12;
  connOptions.nLocalServices = ServiceFlags(NODE_NETWORK | NODE_WITNESS);
  connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
  connOptions.nMaxAddnode = 12;
  connOptions.vSeedNodes = config.vec_seed_;
  connOptions.nListenPort = config.listen_port_;
  return ambr::p2p::init(std::move(connOptions));
}

}
}
