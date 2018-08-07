#ifndef AMBR_UTILS_VALIDATOR_AUTO_H_
#define AMBR_UTILS_VALIDATOR_AUTO_H_
#include <core/key.h>
#include <thread>
#include <atomic>
namespace ambr {
namespace utils {

class ValidatorAuto{
public:
  ValidatorAuto();
  void StartAutoRun(const core::PrivateKey& pri_key);
  void StopAutoRun();
private:
  std::thread* thread_;
  std::atomic<bool> run_;
  const uint64_t publish_interval_ = 2000u;
};
}
}

#endif
