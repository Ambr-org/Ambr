#ifndef AMBR_P2P_NET_BASE_H
#define AMBR_P2P_NET_BASE_H
#include <iostream>
#include <boost/asio.hpp>
#include "netaddress.h"

namespace ba = boost::asio;
#define SOCKET boost::asio::ip::tcp::socket

namespace Ambr {
  namespace P2P {
    class NetBase {
    public:
      NetBase(boost::asio::io_context&  io)
        :socket_(io),
        io_(io){

      }

      static const int BUFFSIZE = 128;
      SOCKET& socket();
      bool ConnectSocket(NetAddress&);
      void CloseSocet();

      std::string Read();
      std::size_t Write(std::string);

      static std::string Read(SOCKET&);
      static std::size_t Write(SOCKET&, std::string);

    private:
      boost::asio::ip::tcp::socket socket_;
      boost::asio::io_context& io_;
    };
  };
};

#endif // !AMBR_P2P_NET_BASE_H
