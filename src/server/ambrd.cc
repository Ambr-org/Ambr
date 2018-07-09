
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Written by kan                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <string>
#include <platform.h>
#include "ambrd.h"

namespace ambr {
namespace server {

int DoServer() {
    crow::SimpleApp app;

    CROW_ROUTE(app,"/<string>")
    ([](std::string name){
        if (name.size() <= 1)
            return crow::response(400);

        std::ostringstream os;
        os << "Welcome to Ambr console: " << name;
        return crow::response(os.str());
    });

    CROW_ROUTE(app, "/")([](){
        return crow::response(ambr::arch::test().c_str());
    });

    app.port(8080).multithreaded().run();

    return 0;
}

};
};