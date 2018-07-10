/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef AMBR_SERVER_SERVER_H
#define AMBR_SERVER_SERVER_H

#include <iostream>
#include <cassert>
#include <string>
#include <set>

#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/filesystem.hpp>
#include <core/key.h>

namespace po = boost::program_options;
namespace pt = boost::property_tree;
namespace fs = boost::filesystem;
//TODO 命名空间 成员变量 函数命名 tab 参数 const&

namespace Ambr{
namespace Server{

class ServerInterface {
public:
  ServerInterface();

  std::string GetHelpMsg();
  std::string ParserArgs(const std::string &);
  std::string ParserArgs(const std::string &,const std::string &,const std::string &, const int &);
  std::string ParserArgs(const std::string &,const std::string &);
  std::string ParserArgs(int, char*[]);

  void AddNodeOption();
  std::string HandleNodeOption();

private:
  po::options_description desc_;
  po::variables_map vm_;
};

};
};


#endif