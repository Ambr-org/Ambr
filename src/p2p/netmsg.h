#ifndef AMBR_P2P_NETMSG_H
#define AMBR_P2P_NETMSG_H
#include "netbase.h"

#include <string>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <array>

namespace Ambr{
  namespace P2P {
    class NetMsg
    {
      /* NetMsg Format */
 /*     struct NetMessage {
        uint32_t version_;
        uint32_t len_;
        uint32_t command_;
        std::string str_msg_;
      };*/

    public:
      typedef std::array<unsigned char, Ambr::P2P::NetBase::BUFFSIZE> buffertype;
      static const int HEADR_SIZE = 4;
      static const int MAX_DATA_SIZE = 512;
      static const int P2P_VERSION = 0x001;
      static const unsigned short UINT_SIZE = 8;
      static const unsigned short HEADER_SIZE = 3 * UINT_SIZE;

      NetMsg(uint32_t version,uint32_t command, std::string str_msg);
      NetMsg(uint32_t version, uint32_t command);

      NetMsg();
  
      void SerializeMany() {}

      template <typename T, typename... Args>
      void SerializeMany(T version, Args&&... args)
      {
        Serialize(version);
        SerializeMany(args...);
      }

      void Serialize(std::string p)
      {
        if (npos_ + p.size() < Ambr::P2P::NetBase::BUFFSIZE) {
          std::copy(p.begin(), p.end(), buffer_.begin() + npos_);
          npos_ += p.size();
        }
        else {
          std::cerr << "buff memory run out" << std::endl;
        }
      }

      static std::vector<NetMsg> Deserialize(buffertype,std::size_t);
  
      void Serialize(uint32_t arg) {
        if (npos_ + UINT_SIZE < Ambr::P2P::NetBase::BUFFSIZE) {
          std::stringstream stream;
          stream << std::setw(UINT_SIZE) << std::setfill('0') << std::hex << arg;
          auto str = stream.str();
          std::copy(str.begin(), str.end(), buffer_.begin() + npos_);
          npos_ += UINT_SIZE;
        }
        else {
          std::cerr << "buff memory run out" << std::endl;
        }       
      }

      // Serialize local netmsg
      void Serialize();

      void Print() {
        std::copy(buffer_.begin(), buffer_.begin() + npos_, std::ostream_iterator<char>(std::cout, ""));
        std::cout << std::endl;
        std::cout << "npos_ = " << npos_ << std::endl;
      }

      buffertype buffer() {
        return buffer_;
      }

      std::size_t pos() {
        return npos_;
      }

      void ToString() {
        std::cout << "Version: " << version_ << std::endl
          << "Len: " << len_ << std::endl
          << "Command: " << command_ << std::endl
          << "str_msg: " << str_msg_ << std::endl;
      }
      
    private:
      buffertype buffer_;
      std::size_t npos_;

      uint32_t version_;
      uint32_t len_;
      uint32_t command_;
      std::string str_msg_;
    };  

  };
};



#endif // !AMBR_P2P_NETMSG_H



