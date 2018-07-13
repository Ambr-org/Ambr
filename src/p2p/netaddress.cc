#include "netaddress.h"

std::string Ambr::P2P::NetAddress::GetSockAddr()
{
  return std::string();
}

void Ambr::P2P::NetAddress::SetSockAddr(std::string addr)
{
  address_ = std::move(addr);
}

unsigned short Ambr::P2P::NetAddress::GetPort()
{
  return port_;
}

std::string Ambr::P2P::NetAddress::ToString()
{
  return std::string();
}

std::string Ambr::P2P::NetAddress::ToStringPort()
{
  return std::to_string(port_);
}
