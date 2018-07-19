#ifndef AMBR_P2P_NETMSG_H
#define AMBR_P2P_NETMSG_H

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
    public:
      static const int HEADR_SIZE = 4;
      static const int MAX_DATA_SIZE = 512;

      NetMsg()
        :npos_(HEADR_SIZE),
        msghdr_({ 0 })
      {

      }

      

      void SerializeMany() {

      }

      void Encode_header() {
        std::stringstream stream;
        stream << std::setw(HEADR_SIZE) << std::setfill('0') << npos_;
        auto str = stream.str();
        std::copy(str.begin(), str.end(), buffer_.begin());

        msghdr_.data_len = npos_ - HEADR_SIZE;
      }

      static void Decode_Header(std::array<unsigned char, 128> buff, std::size_t length) {
        int maxsize = 128;
        int current_pos = 0;
        while (current_pos + 4 < length) {
          char len[128] = { 0 };
          std::copy(buff.begin() + current_pos, buff.begin() + current_pos + HEADR_SIZE, len);
          current_pos += 4;
          auto data_size = std::stoi(len);
          if (current_pos + data_size > length) {
            break;
          }
          std::copy(buff.begin() + current_pos, buff.begin() + current_pos + data_size, len);
          std::cout.write(len, data_size);

          current_pos += data_size;
        }     
      }

      template <typename... Args>
      void SerializeMany(std::string p, Args&&... args)
      {
        Serialize(p);
        SerializeMany(args...);
      }

      void Serialize(std::string p)
      {
        if (p.size() + npos_ > 128) {
          npos_ = 0;
        }

        std::copy(p.c_str(), p.c_str() + p.size(), buffer_.begin() + npos_);
        npos_ += p.size();
      }

      void Print() {
        std::copy(buffer_.begin(), buffer_.begin() + npos_, std::ostream_iterator<char>(std::cout, ""));
        std::cout << std::endl;
      }

      std::array<unsigned char, 128> buffer_;
      std::size_t npos_;
    private:
      struct MsgHdr {
        std::size_t data_len;
      };

      struct MsgHdr msghdr_;    
    };    
  };
};



#endif // !AMBR_P2P_NETMSG_H



