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
      Peer(SOCKET socket)
        :socket_(std::move(socket))
      {}

      std::string GetAddrLocal();
      static bool ValidateAddr(SOCKET&);
      static std::string ProcessMessage(std::string);
      SOCKET socket_;
    private:
      
      std::vector<std::string> sendbuffer_;
      std::vector<std::string> recvbuffer_;

      int refcount_;

    };
  };
};


#endif // !AMBR_P2P_PEER_H
