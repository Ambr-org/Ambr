
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

namespace ambr {
namespace server {

int DoServer() {
    crow::SimpleApp app;
	Ambr::Server::ServerInterface server_interface;

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

    return 0;
}

};
};