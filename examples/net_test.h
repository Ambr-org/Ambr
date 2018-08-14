#ifndef _AMBR_EXAMPLES_NET_TEST_H_
#define _AMBR_EXAMPLES_NET_TEST_H_

#include "net.h"
#include "core/unit.h"

#include <boost/asio.hpp>
#include <time.h>
#include <atomic>
#include <list>
#include <memory.h>
#include <functional>
#include <boost/threadpool.hpp>
//TODO:upnp
//TODO:PING PONG
//TODO:maintenance server list

using Ptr_Unit = std::shared_ptr<ambr::core::Unit>;

namespace ambr{
namespace store{
  class StoreManager;
}

namespace net{
enum MessageCommand{
  //check version, first message after connected
  //str_msg_ is no use
  MC_INVALIDATE = 1,
  //after check version,need broadcast address
  /*
  |-------------------------------|
  |name      |size|type    |limit |
  |-------------------------------|
  |addr_count|2   |uint16  |<=1000|
  |-------------------------------|
  |addr      |4   |uint32  |      |
  |-------------------------------|
  |port      |2   |uint16  |      |
  |-------------------------------|
  */
  MC_ADDR = 2,
  MC_NEW_UNIT =3,
  MC_NEW_SECTION = 4,
  MC_NEW_SECTION_UNIT = 5,
};

class NetMessageAddr{
public:
  std::list<std::pair<boost::asio::ip::address_v4, uint16_t>> addr_list_;
  bool DecodeFromString(const std::string& str){
    if(str.size() < 8 ||str.size()%6 !=2){
      return false;
    }
    uint32_t idx = 0;
    uint16_t addr_count = *(uint16_t*)(str.data()+idx);
    idx+=2;
    if(addr_count > 1000 || addr_count != str.size()/6){
      return false;
    }
    for(int i = 0; i < addr_count; i++){
      uint32_t addr = *(uint32_t*)(str.data()+idx);
      idx += 4;
      uint16_t port = *(uint32_t*)(str.data()+idx);
      idx += 2;
      std::pair<boost::asio::ip::address_v4, uint16_t> item;
      item.first = boost::asio::ip::address_v4(addr);
      item.second = port;
      addr_list_.push_back(item);
    }
    return true;
  }
  std::string EncodeToString(){
    std::string str_rtn;
    str_rtn.resize(addr_list_.size()*6+2);
    uint16_t addr_count = addr_list_.size();
    uint32_t idx = 0;
    memcpy((void*)(str_rtn.data()+idx), &addr_count, sizeof(addr_count));
    idx += sizeof(addr_count);
    //std::list<std::pair<boost::asio::ip::address_v4, uint16_t>>
    for(std::pair<boost::asio::ip::address_v4, uint16_t> item:addr_list_){
      uint32_t addr = item.first.to_uint();
      memcpy((void*)(str_rtn.data()+idx), &addr, sizeof(addr));
      idx+=sizeof(addr);
      uint16_t port = item.second;
      memcpy((void*)(str_rtn.data()+idx), &port, sizeof(port));
      idx+=sizeof(port);
    }
    return str_rtn;
  }
};

struct NetMessage{
  uint32_t version_;
  uint32_t len_;
  uint32_t command_;
  std::string str_msg_;
  static const uint32_t HEAD_SIZE=12;
};

struct IPConfig{
  uint32_t port_;
  std::string str_ip_;
};

struct NetManagerConfig{
  uint32_t max_in_peer_;
  uint32_t max_out_peer_;
  uint32_t max_in_peer_for_optimize_;
  uint32_t max_out_peer_for_optimize_;
  uint16_t listen_port_;
  std::vector<boost::asio::ip::tcp::endpoint> seed_list_;
  bool use_upnp_;
  bool use_nat_pmp_;
  bool use_natp_;
  uint32_t heart_time_;//second of heart interval
  std::vector<IPConfig> vec_seed_;
};

/*connection info
 thread safety
 */
class Peer{
public:
  boost::asio::ip::tcp::endpoint end_point_;//thread safety
  std::atomic<uint32_t> version_;
  std::atomic<uint32_t> pre_version_;//prepare accept version
  std::atomic<uint32_t> ping_pang_delay_;//msec of net delay
  std::atomic<std::time_t> connected_time_;
  std::shared_ptr<boost::asio::ip::tcp::socket> socket_;
  boost::asio::deadline_timer timer_;
  boost::asio::io_service* ios_;
  std::vector<uint8_t> buf_;
  std::list<std::shared_ptr<NetMessage>> msg_list_for_send_;
  uint32_t sending_;
public:
  void Start();
  void SendMessage(std::shared_ptr<NetMessage> msg);
  void OnReceiveMessage(std::shared_ptr<std::vector<uint8_t>> buf, size_t translated, const boost::system::error_code& ec);
  void OnSendMessage(std::shared_ptr<std::vector<uint8_t>> buf, size_t translated, const boost::system::error_code& ec);
public:
  std::function<void(std::shared_ptr<NetMessage>)> OnReceiveMessageFunc;
  std::function<void(const boost::system::error_code& ec)> OnDisconnectFunc;
  Peer(boost::asio::io_service* ios):
    version_(0),
    pre_version_(0),
    ping_pang_delay_(0),
    connected_time_(0),
    timer_(*ios),
    ios_(ios),
    sending_(false){

  }
};

class NetManager{
public:
  NetManager(std::shared_ptr<store::StoreManager> store_manager);
  bool init(const NetManagerConfig& config);
  void SetOnReceive(std::function<void(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer)> func);
  void SendMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer);
  //send message to all validate peers except peer in param
  void BoardcastMessage1(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer);
  void SetOnDisconnect(std::function<void(std::shared_ptr<Peer>)> func);
  void SetOnAccept(std::function<void(std::shared_ptr<Peer>)> func);
  void SetOnConnected(std::function<void(std::shared_ptr<Peer>)> func);
  void RemovePeer(std::shared_ptr<Peer> peer, uint32_t second);
public:
  void RemovePeer(CNode* p_node, uint32_t second);
  void BoardcastMessage(CSerializedNetMsg&& msg, CNode* p_node);
  void SetOnAcceptNode(const std::function<void(CNode*)>& func);
  void SetOnConnectedNode(const std::function<void(CNode*)>& func);
  void SetOnDisconnectNode(const std::function<void(CNode*)>& func);

  class Impl;
private:
  Impl* impl_;
};
}
}
#endif
