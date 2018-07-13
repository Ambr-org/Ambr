#ifndef AMBR_P2P_NET_BASE_H
#define AMBR_P2P_NET_BASE_H
#include <iostream>

#include "netaddress.h"

#define SOCKET int

namespace Ambr {
  namespace P2P {
    struct NetBase {
      NetBase();
      SOCKET CreateSocket(NetAddress);
      void ConnectSocket(SOCKET);
      void CloseSocet(SOCKET);
    };
  };
};

#endif // !AMBR_P2P_NET_BASE_H
