#include "validator_auto.h"
#include <boost/thread.hpp>
#include <boost/date_time.hpp>
#include <iostream>
#include <store/store_manager.h>
ambr::utils::ValidatorAuto::ValidatorAuto():thread_(nullptr){

}

void ambr::utils::ValidatorAuto::StartAutoRun(const ambr::core::PrivateKey &pri_key){
  if(thread_)StopAutoRun();
  run_ = true;
  thread_ = new std::thread([&,pri_key](){
    uint64_t last_nonce = 0;
    uint64_t now_nonce = 0;
    uint64_t interval = 0;
    while(run_){
      boost::posix_time::ptime pt = boost::posix_time::microsec_clock::universal_time();
      boost::posix_time::ptime pt_ori(boost::gregorian::date(1970, boost::gregorian::Jan, 1));
      boost::posix_time::time_duration duration = pt-pt_ori;
      interval = duration.total_milliseconds() - ambr::store::GetStoreManager()->GetGenesisTime();
      now_nonce = (interval/publish_interval_);
      if(now_nonce > last_nonce){
        last_nonce = now_nonce;
        std::cout<<interval<<":"<<now_nonce<<std::endl;
        ambr::core::PublicKey now_pub_key;
        if(ambr::store::GetStoreManager()->GetValidatorSet()->GetNonceTurnValidator(now_nonce, now_pub_key)){
          std::cout<<"Need prikey:"<<pri_key.encode_to_hex()<<std::endl;
          std::cout<<"Need pubkey:"<<ambr::core::GetPublicKeyByPrivateKey(pri_key).encode_to_hex()<<std::endl;
          if(now_pub_key == ambr::core::GetPublicKeyByPrivateKey(pri_key)){
            std::cout<<"MyTurns:"<<now_pub_key.encode_to_hex()<<std::endl;
          }
          else{
            std::cout<<"OtherTurns:"<<now_pub_key.encode_to_hex()<<std::endl;
          }
        }
      }
      boost::this_thread::sleep(boost::posix_time::millisec(100));
    }
  });
}

void ambr::utils::ValidatorAuto::StopAutoRun(){
  run_ = false;
  thread_->join();
  delete thread_;
  thread_ = nullptr;
}
