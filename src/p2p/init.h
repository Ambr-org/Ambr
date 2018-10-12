#ifndef AMBR_P2P_INIT_H
#define AMBR_P2P_INIT_H

#include <net.h>
#include <shutdown.h>

namespace ambr{
  namespace p2p{
    bool init(CConnman::Options&&);

    // p2p interface
    void SendMessage(CNode* p_node, CSerializedNetMsg&& msg);
    void BroadcastMessage(CSerializedNetMsg&& msg);
    void RemoveNode(CNode* pNode);
  };
};
#endif
