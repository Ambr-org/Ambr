#ifndef AMBR_UTILS_VALIDATOR_AUTO_H_
#define AMBR_UTILS_VALIDATOR_AUTO_H_

#include <thread>
#include <atomic>
#include <memory>
#include <boost/signals2/connection.hpp>
#include <core/key.h>
#include <core/unit.h>
namespace ambr {
namespace store{
  class StoreManager;
}
namespace utils {

class ValidatorAuto{
public:
  ValidatorAuto(std::shared_ptr<store::StoreManager> store_manager);
  ~ValidatorAuto();
public:
  void StartAutoRun(const core::PrivateKey& pri_key);
  void StopAutoRun();
  void OnNeedVote(std::shared_ptr<core::ValidatorUnit> validator_unit);
private:
  std::shared_ptr<store::StoreManager> store_manager_;
  std::thread* thread_;
  std::atomic<bool> run_;
  core::PrivateKey private_key_;
};
}
}

#endif
