#ifndef AMBR_P2P_NETADDRESS_H
#define AMBR_P2P_NETADDRESS_H

#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

namespace Ambr {
  namespace P2P {
    class NetAddress {
    public:
      NetAddress(const std::string ip, const unsigned short port)
        :address_(std::move(ip)),
        port_(port){

      }

      NetAddress(const std::string ip)
        :address_(std::move(ip)),
         port_(DEFAULT_PORT){

      }
      static const unsigned short DEFAULT_PORT = 8000;
      std::string GetSockAddr();
      void SetSockAddr(std::string addr);

      unsigned short GetPort();

      std::string ToString();
      std::string ToStringPort();

    private:
      std::string address_;
      unsigned short port_;

    };
  };
};

#endif // !AMBR_P2P_NETADDRESS_H
