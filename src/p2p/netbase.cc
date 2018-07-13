#include "netbase.h"
#include <boost/asio.hpp>
#include <boost/bind.hpp>

Ambr::P2P::NetBase::NetBase()
{
}

SOCKET Ambr::P2P::NetBase::CreateSocket(NetAddress)
{
  return 10;
}

void Ambr::P2P::NetBase::ConnectSocket(SOCKET)
{
}

void Ambr::P2P::NetBase::CloseSocet(SOCKET)
{
}
