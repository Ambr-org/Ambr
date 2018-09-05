
#include <iostream>
#include <core/node.h>
#include <gtest/gtest.h>
#include <glog/logging.h>

#include "store/store_manager.h"
#include <boost/thread.hpp>
TEST (UnitTest, Store) {
  std::string root_pri_key = "25E25210DCE702D4E36B6C8A17E18DC1D02A9E4F0D1D31C4AEE77327CF1641CC";
  ambr::store::StoreManager* manager = new ambr::store::StoreManager();
  ambr::core::PrivateKey test_pri = ambr::core::CreateRandomPrivateKey();
  ambr::core::PublicKey test_pub = ambr::core::GetPublicKeyByPrivateKey(test_pri);

  system("rm -fr ./aaa");
  manager->Init("./aaa");

  ambr::core::UnitHash test_hash;
  std::shared_ptr<ambr::core::Unit> added_unit;
  ambr::core::Amount send_ammout = 1000*manager->GetTransectionFeeBase();
  std::string err;
  ambr::core::Amount balance_ori;
  ambr::core::Amount balance_used;
  ambr::core::Amount balance_remainder;

  size_t used_byte = 0;
  //===last_unit_hash===========================
  //test send 1----->SendToAddress
  {
    //regular operate
    EXPECT_TRUE(manager->GetBalanceByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), balance_ori));
    for(int i = 0; i < 12; i++){
      balance_used = balance_used+send_ammout;
      bool result;
      EXPECT_TRUE((result = manager->SendToAddress(test_pub, send_ammout, root_pri_key, &test_hash, added_unit, &err)));
      used_byte += added_unit->GetFeeSize();
      if(!result){
        std::cout<<err<<std::endl;
      }
      send_ammout = send_ammout*10;
    }
    //param test
    ambr::core::Amount amount_test = 1000*manager->GetTransectionFeeBase();
    EXPECT_TRUE(manager->SendToAddress(test_pub, amount_test, root_pri_key, nullptr, added_unit, nullptr));
    balance_used = balance_used+amount_test;
    used_byte+=added_unit->GetFeeSize();
    EXPECT_TRUE(manager->GetBalanceByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), balance_remainder));
    EXPECT_EQ(balance_remainder, balance_ori-balance_used);

    //incorrect operate
    //error private key
    EXPECT_FALSE(manager->SendToAddress(test_pub, send_ammout, ambr::core::CreateRandomPrivateKey(), &test_hash, added_unit, &err));
    //error send_ammout(bigger than remainder)
    EXPECT_FALSE(manager->SendToAddress(test_pub, balance_remainder+amount_test, root_pri_key, &test_hash, added_unit, &err));
  }

  //==============================
  //test send 2
  {
    //regular operate------>AddSendUnit
    std::shared_ptr<ambr::core::SendUnit> send_unit = std::make_shared<ambr::core::SendUnit>();
    std::list<std::shared_ptr<ambr::store::UnitStore> > trade_history = manager->GetTradeHistoryByPubKey(ambr::core::GetPublicKeyByPrivateKey(root_pri_key), 10);
    send_unit->set_version((uint32_t)0x00000001);
    send_unit->set_type(ambr::core::UnitType::send);
    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(root_pri_key));
    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->set_balance(balance_remainder - 10000);
    send_unit->set_dest(test_pub);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_TRUE(manager->AddSendUnit(send_unit, nullptr));

    //incorrect operate
    send_unit->set_version((uint32_t)0x00000002);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_version((uint32_t)0x00000001);
    send_unit->set_type(ambr::core::UnitType::receive);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_type(ambr::core::UnitType::send);
    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(test_pri));
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(test_pri);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_public_key(ambr::core::GetPublicKeyByPrivateKey(root_pri_key));
    send_unit->set_prev_unit(trade_history.back()->GetUnit()->hash());
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->CalcHashAndFill();
    send_unit->set_balance(balance_remainder +1);
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));


    send_unit->set_prev_unit(trade_history.front()->GetUnit()->hash());
    send_unit->set_balance(balance_remainder +1);
    send_unit->CalcHashAndFill();
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->set_balance(balance_remainder);
    send_unit->set_hash(ambr::core::CreateRandomPrivateKey());
    send_unit->SignatureAndFill(root_pri_key);
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));

    send_unit->CalcHashAndFill();
    send_unit->set_sign(ambr::core::Signature());
    EXPECT_FALSE(manager->AddSendUnit(send_unit, nullptr));
  }
  {//test receive1 ------>ReceiveFromUnitHash
    //regular operate
    std::list<ambr::core::UnitHash> wait_list = manager->GetWaitForReceiveList(test_pub);

    EXPECT_TRUE(wait_list.size() == 14);
    for(size_t i = 0; i < 13; i++){
      {//incorrect operate
        EXPECT_FALSE(manager->ReceiveFromUnitHash("12345", test_pri, &test_hash, added_unit, &err));
        EXPECT_FALSE(manager->ReceiveFromUnitHash(wait_list.front(), test_pri+1, &test_hash, added_unit, &err));
      }
      EXPECT_TRUE(manager->ReceiveFromUnitHash(wait_list.front(), test_pri, &test_hash, added_unit, &err));
      used_byte += added_unit->GetFeeSize();
      wait_list.pop_front();
    }
    ambr::core::Amount test_amount;
    EXPECT_TRUE(manager->GetBalanceByPubKey(test_pub, test_amount));
    EXPECT_TRUE(test_amount == balance_used - used_byte*manager->GetTransectionFeeBase());
  }

  {//test receive2 ------>AddReceiveUnit
    ambr::core::UnitHash last_unit_hash;
    ambr::core::Amount receive_amount;
    ambr::core::UnitHash receive_from_hash;
    ambr::core::Amount old_balance;

    EXPECT_TRUE(manager->GetLastUnitHashByPubKey(test_pub, last_unit_hash));
    std::list<ambr::core::UnitHash> wait_list = manager->GetWaitForReceiveList(test_pub);
    EXPECT_TRUE(wait_list.size() == 1);
    receive_from_hash = wait_list.front();
    EXPECT_TRUE(manager->GetSendAmount(receive_from_hash, receive_amount, &err));
    manager->GetBalanceByPubKey(test_pub, old_balance);

    std::shared_ptr<ambr::core::ReceiveUnit> receive_unit = std::make_shared<ambr::core::ReceiveUnit>();

    receive_unit->set_version(0x00000001);
    receive_unit->set_type(ambr::core::UnitType::receive);
    receive_unit->set_public_key(test_pub);
    receive_unit->set_prev_unit(last_unit_hash);
    receive_unit->set_balance(old_balance+receive_amount);
    receive_unit->set_from(receive_from_hash);
    receive_unit->CalcHashAndFill();
    receive_unit->SignatureAndFill(test_pri);

    {//incorrect operate
      receive_unit->set_version(0x00000002);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_version(0x00000001);

      receive_unit->set_type(ambr::core::UnitType::send);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_type(ambr::core::UnitType::receive);

      receive_unit->set_public_key(test_pub+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_public_key(test_pub);

      receive_unit->set_prev_unit(last_unit_hash+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_prev_unit(last_unit_hash);

      receive_unit->set_balance(old_balance+receive_amount+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_balance(old_balance+receive_amount-1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_balance(old_balance+receive_amount);

      receive_unit->set_from(receive_from_hash-1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->set_from(receive_from_hash);

      receive_unit->set_hash(receive_unit->hash()+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->CalcHashAndFill();

      receive_unit->SignatureAndFill(test_pri+1);
      EXPECT_FALSE(manager->AddReceiveUnit(receive_unit, &err));
      receive_unit->SignatureAndFill(test_pri);
    }
    EXPECT_TRUE(manager->AddReceiveUnit(receive_unit, &err));
  }

}
