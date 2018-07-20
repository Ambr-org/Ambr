#ifndef AMBR_P2P_CONNMGT
#define AMBR_P2P_CONNMGT

#include "netaddress.h"
#include "netbase.h"
#include "peer.h"
#include "netmsg.h"

namespace Ambr {
  namespace P2P {
    class ConnMgt
    {
    public:
      ConnMgt(ba::io_context& io_server)
        :acceptor_(io_server, ba::ip::tcp::endpoint(ba::ip::tcp::v4(), Ambr::P2P::NetAddress::DEFAULT_PORT))
      {
        start();
      }

      void start();

      void accept_conn();
      void PushMsg(Ambr::P2P::NetAddress);

    private:
      struct Session
        :public std::enable_shared_from_this<Session>
      {
         Session(SOCKET socket)
           :socket_(std::move(socket))
         {}
         void Read();
         void Write(std::string);

         std::array<unsigned char, Ambr::P2P::NetBase::BUFFSIZE> buffer_;
         SOCKET socket_;
      };

      std::vector<Ambr::P2P::Peer> peers_;
      boost::asio::io_context io_client_;
      ba::ip::tcp::acceptor acceptor_;
    };
  };
};



#endif // !AMBR_P2P_CONNMGT
