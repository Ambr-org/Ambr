
#include <core/unit.h>
#include <iostream>

int main(){
  ambr::core::SendUnit send_unit;
  send_unit.set_version(0x00000001);
  send_unit.set_type(ambr::core::UnitType::send);
  send_unit.set_public_key("0x20000002");
  send_unit.set_prev_unit("0x20000003");
  send_unit.set_balance("0x20000004");
  send_unit.set_hash("0x20000005");
  send_unit.set_sign("0x20000006");
  send_unit.set_dest("0x20000007");
  send_unit.CalcHashAndFill();
  send_unit.SignatureAndFill("0x1234567890123456789012345678901234567890123456789012345678901111");
  std::string json = send_unit.SerializeJson();
  std::cout<<"serial_json:"<<std::endl<<json<<std::endl<<std::endl<<std::endl;

  ambr::core::SendUnit unit_1;
  unit_1.DeSerializeJson(json);
  std::cout<<"de serial_json:"<<std::endl<<unit_1.SerializeJson()<<std::endl<<std::endl<<std::endl;
  send_unit.set_version(0x00000001);
  send_unit.set_type(ambr::core::UnitType::send);
  send_unit.set_public_key("0x10000002");
  send_unit.set_prev_unit("0x10000003");
  send_unit.set_balance("0x10000004");
  send_unit.set_hash("0x10000005");
  send_unit.set_sign("0x10000006");
  send_unit.set_dest("0x10000007");
  std::vector<uint8_t> buf = send_unit.SerializeByte();
  ambr::core::SendUnit unit_2;
  unit_2.DeSerializeByte(buf);
  std::cout<<"de serial_byte:"<<std::endl<<unit_2.SerializeJson()<<std::endl<<std::endl<<std::endl;
  return 0;
}
