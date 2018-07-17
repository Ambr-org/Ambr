#include "netaddress.h"

std::string Ambr::P2P::NetAddress::GetSockAddr()
{
  return std::string();
}

void Ambr::P2P::NetAddress::SetSockAddr(std::string addr)
{
  address_ = std::move(addr);
}

std::vector<Ambr::P2P::NetAddress*> Ambr::P2P::NetAddress::SelectAddress(int count)
{
  std::vector<Ambr::P2P::NetAddress*> addrs;

  //test net 
  for (int i = 0; i < count; i++) {
    auto address = new NetAddress("localhost", 8001 + i);
    addrs.push_back(address);
  }
  
  return addrs;
}

const unsigned short Ambr::P2P::NetAddress::GetPort()
{
  return port_;
}

std::string Ambr::P2P::NetAddress::ToString()
{
  std::string addr;
  addr.append(address_).append(":").append(ToStringPort());
  return addr;
}

const std::string Ambr::P2P::NetAddress::ToStringPort()
{
  return std::to_string(port_);
}
