#include "peer.h"


bool Ambr::P2P::Peer::ValidateAddr(SOCKET&)
{
  return true;
}


std::string Ambr::P2P::Peer::ProcessMessage(std::string data)
{
  std::cout << data << std::endl;
  return data;
}
