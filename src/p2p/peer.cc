#include "peer.h"

std::string Ambr::P2P::Peer::GetAddrLocal()
{
  return netaddr_.GetSockAddr();
}
