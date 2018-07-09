
#include <iostream>
#include <platform.h>
#include <server/ambrd.h>
#include <server/server_interface.h>
#include <core/node.h>

int main(int argc, char* argv[]) {
  try{  
	Ambr::Server::ServerInterface server_interface;
	std::cout << server_interface.ParserArgs(argc, argv) << std::endl;
  }
  catch (std::exception & e){
    std::cerr << "error: " << e.what() << std::endl;
  }
  catch (...){
    std::cerr << "Unknown exception" << std::endl;
  }
  return 0;
}
