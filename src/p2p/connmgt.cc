#include "connmgt.h"

void Ambr::P2P::ConnMgt::start()
{
  accept_conn();
  auto address = Ambr::P2P::NetAddress::SelectAddress(1);
  for (int i = 0; i < 1; i++) {
    NetBase netbase(io_client_);
    if (!netbase.ConnectSocket(*address[i])) {
      continue;
    }

    if (Ambr::P2P::Peer::ValidateAddr(netbase.socket())) {
      peers_.push_back(Ambr::P2P::Peer(std::move(netbase.socket())));
    }
    else {
      netbase.CloseSocet();
    }
  }
}


void Ambr::P2P::ConnMgt::accept_conn()
{
  acceptor_.async_accept(
    [this](boost::system::error_code ec, ba::ip::tcp::socket socket)
  {
    if (!ec)
    {
      std::cout << socket.remote_endpoint().address().to_string() << std::endl;
      std::make_shared<Session>(std::move(socket))->Read();
    }
    else {
      socket.close();
    }

    accept_conn();
  });
}

void Ambr::P2P::ConnMgt::Session::Read()
{
  auto self(shared_from_this());
  socket_.async_read_some(boost::asio::buffer(buffer_, Ambr::P2P::NetBase::BUFFSIZE),
    [this, self](boost::system::error_code ec, std::size_t len)
  {
    if (!ec)
    {
      auto msgs = Ambr::P2P::NetMsg::Deserialize(buffer_, len);
      for (auto msg : msgs) {
        msg.ToString();
      }
    }
  });
}

void Ambr::P2P::ConnMgt::Session::Write(std::string data)
{
  auto self(shared_from_this());
  //TODO can not use like this, check 
  //boost::asio::buffer(data);

  boost::asio::async_write(socket_, boost::asio::buffer(data.c_str(), data.size()),
    [this, self](boost::system::error_code ec, std::size_t /*length*/)
  {
    if (!ec)
    {
    }
  });
}


