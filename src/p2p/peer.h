#ifndef AMBR_P2P_PEER_H
#define AMBR_P2P_PEER_H
#include "netaddress.h"
#include "netbase.h"
#include <vector>
#include <string>

namespace Ambr {
  namespace P2P {
    class Peer {
    public:
      Peer(NetAddress netaddr)
        :netaddr_(std::move(netaddr)){
      }

      std::string GetAddrLocal();
    private:
      SOCKET socket_;
      NetAddress netaddr_;
      std::vector<std::string> sendbuffer_;
      std::vector<std::string> recvbuffer_;

      int refcount_;

    };
  };
};


#endif // !AMBR_P2P_PEER_H
