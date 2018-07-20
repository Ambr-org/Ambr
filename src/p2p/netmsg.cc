#include "netmsg.h"

Ambr::P2P::NetMsg::NetMsg(uint32_t version, uint32_t command, std::string str_msg)
  :version_(version),
   command_(command),
   str_msg_(std::move(str_msg)),
   len_(str_msg.size()),
   npos_(0)
{

}

Ambr::P2P::NetMsg::NetMsg(uint32_t version, uint32_t command)
  :version_(version),
  command_(command),
  len_(0)
{

}

Ambr::P2P::NetMsg::NetMsg()
  :version_(P2P_VERSION),
   len_(0),
   npos_(0)
{
}

void Ambr::P2P::NetMsg::Serialize()
{
  SerializeMany(version_, len_, command_, str_msg_);  
}

std::vector<Ambr::P2P::NetMsg> Ambr::P2P::NetMsg::Deserialize(buffertype buffer, std::size_t pos){
  std::vector<Ambr::P2P::NetMsg> netmsgs;
  int currentpos = 0;
  NetMsg msg;
  char data[Ambr::P2P::NetBase::BUFFSIZE] = { 0 };

  while (currentpos + HEADER_SIZE <= pos) {
    uint32_t version;
    std::copy(buffer.begin() + currentpos, buffer.begin() + currentpos + UINT_SIZE, data);
    std::stringstream stream;
    stream.write(data, UINT_SIZE);
    stream >> std::hex >> version;
    currentpos += UINT_SIZE;

    uint32_t len;
    stream.clear();
    std::copy(buffer.begin() + currentpos, buffer.begin() + currentpos + UINT_SIZE, data);
    stream.write(data, UINT_SIZE);
    stream >> std::hex >> len;
    currentpos += UINT_SIZE;

    uint32_t command;
    stream.clear();
    std::copy(buffer.begin() + currentpos, buffer.begin() + currentpos + UINT_SIZE, data);
    stream.write(data, UINT_SIZE);
    stream >> std::hex >> command;
    currentpos += UINT_SIZE;

    if (len > 0) {
      std::copy(buffer.begin() + currentpos, buffer.begin() + currentpos + len, data);
      std::string str_msg(data, data + len);
      currentpos += len;
      netmsgs.push_back(NetMsg(version, command, str_msg));
    }
    else {
      netmsgs.push_back(NetMsg(version, command));
    }   
  }

  return netmsgs;
}