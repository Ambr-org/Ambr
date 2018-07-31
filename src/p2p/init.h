#ifndef AMBR_P2P_INIT_H
#define AMBR_P2P_INIT_H

#include <net.h>

namespace ambr{
    namespace p2p{
      bool init(CConnman::Options&&);
    };
};


#endif