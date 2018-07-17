#include "netbase.h"
#include <boost/asio.hpp>
#include <boost/bind.hpp>

SOCKET& Ambr::P2P::NetBase::socket()
{
  return socket_;
}

bool Ambr::P2P::NetBase::ConnectSocket(NetAddress& addr)
{
  boost::system::error_code ec;
  boost::asio::ip::tcp::resolver resolver(io_);
  auto ep = resolver.resolve(addr.GetSockAddr(), addr.ToStringPort());

  boost::asio::connect(socket_, ep, ec);

  if (ec) {
    std::cerr << "Can not connect to " << addr.ToString() << std::endl;
    return false;
  }
  else {
    return true;
  }
}

void Ambr::P2P::NetBase::CloseSocet()
{
  boost::asio::post(io_, [this]() { socket_.close(); });
}

std::string Ambr::P2P::NetBase::Read()
{
  std::string data;
  boost::system::error_code ec;
  
  //for (;;) {
    std::array<char, BUFFSIZE> buf;
    std::stringstream stream;

    std::size_t len = socket_.read_some(boost::asio::buffer(buf), ec);
    if (ec == boost::asio::error::eof) {
    //  break;
    }
    else if(ec) {
      throw boost::system::system_error(ec);
    }
    
    stream.write(buf.data(), len);
    data.append(stream.str());
  //}

  return data;
}

std::size_t Ambr::P2P::NetBase::Write(std::string data)
{
  std::size_t len = boost::asio::write(socket_, boost::asio::buffer(data));
  return len;
}

std::string Ambr::P2P::NetBase::Read(SOCKET &socket)
{
  std::string data;
  boost::system::error_code ec;

  //for (;;) {
  std::array<char, BUFFSIZE> buf;
  std::stringstream stream;

  std::size_t len = socket.read_some(boost::asio::buffer(buf), ec);
  if (ec == boost::asio::error::eof) {
    //  break;
  }
  else if (ec) {
    throw boost::system::system_error(ec);
  }

  stream.write(buf.data(), len);
  data.append(stream.str());
  //}

  return data;
}

std::size_t Ambr::P2P::NetBase::Write(SOCKET &socket, std::string data)
{
  std::size_t len = boost::asio::write(socket, boost::asio::buffer(data));
  return len;
}
