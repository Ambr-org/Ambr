
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Written by kan                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <string>
#include <platform.h>
#include "ambrd.h"
#include "server_interface.h"
#include <p2p/net.h>
#include <p2p/utiltime.h>
#include <p2p/shutdown.h>
#include <p2p/net_processing.h>
#include <p2p/init.h>

extern std::unique_ptr<CConnman> g_connman;
extern PeerLogicValidation *peerLogic;

namespace ambr {
namespace server {

void Interrupt()
  {
    if (g_connman)
        g_connman->Interrupt();
  }

void WaitForShutdown()
{
    while (!ShutdownRequested())
    {  
        MilliSleep(200);
    }
    Interrupt();
}

void Shutdown()
{
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;

    TRY_LOCK(cs_Shutdown, lockShutdown);
   
   // StopRPC();
   // StopHTTPServer();


    // Because these depend on each-other, we make sure that neither can be
    // using the other before destroying them.
    if (g_connman) g_connman->Stop();
    //peerLogic.reset();
    g_connman.reset();
}

int DoServer() {
    /*
    crow::SimpleApp app;
	ambr::server::ServerInterface server_interface;

    CROW_ROUTE(app,"/<string>")
    ([&](std::string name){
        return crow::response(server_interface.ParserArgs(name));
    });

    CROW_ROUTE(app,"/<string>/<string>")
    ([&](std::string name, std::string option){
        return crow::response(server_interface.ParserArgs(name, option));
    });

    CROW_ROUTE(app,"/<string>/<string>/<string>/<int>")
    ([&](std::string name, std::string option1, std::string option2,int amount ){
        return crow::response(server_interface.ParserArgs(name, option1, option2, amount));
    });

    CROW_ROUTE(app, "/")
    ([&](){
        return crow::response(server_interface.GetHelpMsg());
    });

    app.port(8080).multithreaded().run();
    */
    auto ret =ambr::p2p::init();
	if (!ret)
    {
        Interrupt();
    } else {
       WaitForShutdown();
    }
    std::cout << "stop" << std::endl;
    Shutdown(); 

    return 0;
}

};
};