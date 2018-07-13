#ifndef AMBR_P2P_CONNMGT
#define AMBR_P2P_CONNMGT

#include "netaddress.h"
#include "netbase.h"

namespace Ambr {
  namespace P2P {
    class ConnMgt {
    public:
      ConnMgt();

      void PushMsg(Ambr::P2P::NetAddress);

    private:
      std::vector<NetAddress> peers_;

    };
  };
};



#endif // !AMBR_P2P_CONNMGT
