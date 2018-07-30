#include "net_test.h"
#include <list>
#include <functional>
#include <boost/bind.hpp>
#include <glog/logging.h>
#include <boost/thread.hpp>
#include <boost/threadpool.hpp>
#include <store/store_manager.h>
std::shared_ptr<ambr::net::NetManager> ambr::net::NetManager::instance;
class ambr::net::NetManager::Impl{
public:
  Impl();
  bool init(const NetManagerConfig& config);
  void SetOnReceive(std::function<void(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer)> func);
  void SendMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer);
  void BoardcastMessage(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer);
  void SetOnDisconnect(std::function<void(std::shared_ptr<Peer>)> func);
  void SetOnAccept(std::function<void(std::shared_ptr<Peer>)> func);
  void SetOnConnected(std::function<void(std::shared_ptr<Peer>)> func);
  void RemovePeer(std::shared_ptr<Peer> peer, uint32_t second);
public:
  void OnAccept(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<boost::asio::ip::tcp::acceptor> acc, const boost::system::error_code& ec);
  void OnConnected(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& ec);

private:
  void ThreadSocketHandle();
  void OnDisconnect(std::shared_ptr<Peer> peer);
  void OnReceive(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer);
private:
  std::vector<boost::asio::ip::address_v4> GetLocalIPs();
  std::vector<boost::asio::ip::address_v4> LookupPublicIPs();
private:
  std::shared_ptr<boost::asio::ip::tcp::acceptor> accept_;
  ambr::net::NetManagerConfig config_;
  std::list<std::shared_ptr<Peer>> in_peers_;
  std::list<std::shared_ptr<Peer>> out_peers_;
  std::list<std::shared_ptr<Peer>> in_peers_wait_;
  std::list<std::shared_ptr<Peer>> out_peers_wait_;
  std::list<boost::asio::ip::tcp::endpoint> server_list_;
private:
  boost::asio::io_service ios_;
  std::thread ios_thread_;
  boost::threadpool::pool thread_pool_;
  std::function<void(std::shared_ptr<NetMessage> msg,  std::shared_ptr<Peer> peer)> on_receive_func_;
  std::function<void(std::shared_ptr<Peer>)> on_disconnect_func_;
  std::function<void(std::shared_ptr<Peer>)> on_accept_func_;
  std::function<void(std::shared_ptr<Peer>)> on_connect_func_;
  bool exit_;
};

ambr::net::NetManager::Impl::Impl():thread_pool_(std::thread::hardware_concurrency()),exit_(false){
  std::vector<boost::asio::ip::address_v4> ips = LookupPublicIPs();
  if(ips.size()){
    server_list_.push_back(boost::asio::ip::tcp::endpoint(ips[0], config_.listen_port_));
  }
}


bool ambr::net::NetManager::Impl::init(const NetManagerConfig &config){
  std::vector<boost::asio::ip::address_v4> ips =  LookupPublicIPs();
  for(boost::asio::ip::address_v4 ip:ips){
    LOG(ERROR)<<ip.to_string();
  }
  config_ = std::move(config);
  //listen
  auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ios_);
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
  ios_thread_ = std::thread(std::bind(&ambr::net::NetManager::Impl::ThreadSocketHandle, this));
  return false;

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

void ambr::net::NetManager::Impl::ThreadSocketHandle(){
  ios_.run();
}

void ambr::net::NetManager::Impl::OnDisconnect(std::shared_ptr<Peer> peer){
  LOG(WARNING)<<"peer disconnect:"<<peer->end_point_.address().to_string()<<":"<<peer->end_point_.port();
  RemovePeer(peer, 0);
  if(on_disconnect_func_)on_disconnect_func_(peer);
}

void ambr::net::NetManager::Impl::OnReceive(std::shared_ptr<NetMessage> msg, std::shared_ptr<Peer> peer){
  if(msg->command_ == MC_INVALIDATE){
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
            addr_msg.addr_list_.push_back(
                  std::pair<boost::asio::ip::address_v4, uint16_t>
                  (addrs[0],
                   config_.listen_port_));
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

  }else if(msg->command_ == MC_ADDR){
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
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ios_);
            socket->async_connect(msg_end_point, boost::bind(&ambr::net::NetManager::Impl::OnConnected, this, socket, boost::asio::placeholders::error));
          }
        }
      }
    }else{
      //TODO
    }
  }else if(msg->command_ == MC_NEW_UNIT){
    std::vector<uint8_t> buf;
    buf.assign(msg->str_msg_.begin(), msg->str_msg_.end());
    std::shared_ptr<ambr::core::Unit> unit = ambr::core::Unit::CreateUnitByByte(buf);
    if(unit){
      LOG(INFO)<<"Get new unit:"<<unit->SerializeJson();
    }
    if(unit->type() == ambr::core::UnitType::send){
      std::shared_ptr<ambr::core::SendUnit> send_unit = std::dynamic_pointer_cast<ambr::core::SendUnit>(unit);
      if(send_unit && ambr::store::GetStoreManager()->AddSendUnit(send_unit, nullptr)){
        BoardcastMessage(msg, peer);
      }
    }else if(unit->type() == ambr::core::UnitType::receive){
      std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::dynamic_pointer_cast<ambr::core::ReceiveUnit>(unit);
      if(receive_unit && ambr::store::GetStoreManager()->AddReceiveUnit(receive_unit, nullptr)){
        BoardcastMessage(msg, peer);
      }
    }
    //ambr::store::GetStoreManager()->AddUnit()
  }else{
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






ambr::net::NetManager::NetManager(){
  impl_ = new Impl();
}

bool ambr::net::NetManager::init(const ambr::net::NetManagerConfig &config){
  return impl_->init(config);
}

void ambr::net::NetManager::SetOnReceive(std::function<void (std::shared_ptr<ambr::net::NetMessage> msg, std::shared_ptr<ambr::net::Peer>)> func){
  return impl_->SetOnReceive(func);
}

void ambr::net::NetManager::SendMessage(std::shared_ptr<ambr::net::NetMessage> msg, std::shared_ptr<ambr::net::Peer> peer){
  impl_->SendMessage(msg, peer);
}

void ambr::net::NetManager::BoardcastMessage(std::shared_ptr<ambr::net::NetMessage> msg, std::shared_ptr<ambr::net::Peer> peer){
  impl_->BoardcastMessage(msg, peer);
}

void ambr::net::NetManager::SetOnDisconnect(std::function<void (std::shared_ptr<ambr::net::Peer>)> func){
  impl_->SetOnDisconnect(func);
}

void ambr::net::NetManager::SetOnAccept(std::function<void (std::shared_ptr<ambr::net::Peer>)> func){
  impl_->SetOnAccept(func);
}

void ambr::net::NetManager::SetOnConnected(std::function<void (std::shared_ptr<ambr::net::Peer>)> func){
  impl_->SetOnConnected(func);
}

void ambr::net::NetManager::RemovePeer(std::shared_ptr<ambr::net::Peer> peer, uint32_t second){
  impl_->RemovePeer(peer, second);
}

std::shared_ptr<ambr::net::NetManager> ambr::net::NetManager::GetInstance(){
  if(!instance){
    instance = std::shared_ptr<ambr::net::NetManager>(new NetManager());
  }
  return instance;
}

void ambr::net::Peer::Start(){
  std::shared_ptr<std::vector<uint8_t>> buf = std::make_shared<std::vector<uint8_t>>();
  buf->resize(NetMessage::HEAD_SIZE);
  boost::asio::async_read(
        *socket_,
        boost::asio::buffer(&((*buf)[0]), buf->size()),
        boost::bind(&ambr::net::Peer::OnReceiveMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error)
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
    boost::asio::async_write(*socket_, boost::asio::buffer(*buf),
                             boost::bind(&ambr::net::Peer::OnSendMessage, this, buf, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));
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
