#include "connmgt.h"

Ambr::P2P::ConnMgt::ConnMgt()
{
  //Test Net
  auto port = Ambr::P2P::NetAddress::DEFAULT_PORT;
  for (auto i = port; i < port + 3; i++) {
    peers_.push_back(NetAddress("localhost", i));
  }
}


int main(int argc, char* argv[])
{

}
