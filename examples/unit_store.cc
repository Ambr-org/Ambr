

#include <iostream>
#include <boost/filesystem.hpp>

#include <store/store_manager.h>
#include <core/key.h>
#include <QApplication>
#include <glog/logging.h>
#include "store_example_main_widget.h"
#include "net_test.h"


int main(int argc, char**argv){
  //init log
  FLAGS_log_dir = ".";
  FLAGS_colorlogtostderr = true;
  google::InitGoogleLogging("Ambr");
  google::SetStderrLogging(google::GLOG_INFO);
  std::shared_ptr<ambr::store::StoreManager> store_manager = std::make_shared<ambr::store::StoreManager>();
  std::shared_ptr<ambr::net::NetManager> net_manager = std::make_shared<ambr::net::NetManager>(store_manager);
  //store_manager->Init("./unit");
  QApplication app(argc, argv);
  StoreExampleMainWidget widget(store_manager, net_manager);
  widget.show();
  app.exec();
  return 0;
}
