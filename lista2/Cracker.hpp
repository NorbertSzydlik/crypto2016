#include <thread>
#include <mutex>
#include <memory>
#include <iterator>
#include <string>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <boost/format.hpp>
#include "utils.hpp"

class Cracker
{
  using Keys = std::vector<Key>;
public:
  Cracker(unsigned int keyLength, const std::string& suffix, const Iv& iv) :
  keyLength_(keyLength),
  suffix_(suffix),
  iv_(iv),
  numOfThreads_(std::thread::hardware_concurrency())
  {
    assert(suffix.size() < keyLength);
    suffixBuf_ = toBytes(boost::multiprecision::cpp_int("0x" + suffix), keyLength / 2);

    suffixBitSize_ = suffix.size() * 4;
  }

  Keys crack(const ByteBuffer& ciphertext)
  {
    const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    ciphertext_ = ciphertext;
    std::copy(std::begin(ciphertext_), std::begin(ciphertext_) + (blockSize), std::back_inserter(ivCiphertext_));
    keys_ = {};
    working_ = true;
    lastPrint_.store(0);
    previousPrintTime_ = std::chrono::system_clock::now();

    std::cout << "Cracking using " << numOfThreads_ << " threads" << std::endl;
    std::vector<std::shared_ptr<std::thread>> threads;
    for(int i = 0; i < numOfThreads_; ++i)
    {
      auto t = std::make_shared<std::thread>([this, i]() {
        crackThread(i);
      });
      threads.push_back(t);
    }
    for(auto& t : threads)
    {
      t->join();
    }
    return keys_;
  }
private:
  void insertKey(const Key& key)
  {
    std::lock_guard<std::mutex> lock(possibleKeyInsertionMutex_);
    keys_.push_back(key);
  }
  void printSpeed()
  {
    const auto printEvery = 1000000;

    if(lastPrint_.fetch_add(1) % printEvery != 0) return;

    auto now = std::chrono::system_clock::now();
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::duration<float, std::ratio<1,1>>>(now - previousPrintTime_).count();

    std::cout << "speed: " << ((float)printEvery/elapsedSeconds) << "/s" << std::endl;

    previousPrintTime_ = now;
  }
  void crackThread(int s)
  {
    Key key = suffixBuf_;

    addOnBit(key, suffixBitSize_, s);

    while(key.size() <= (keyLength_ / 2) && working_)
    {
      printSpeed();
      try
      {
        auto possiblePlaintext = decrypt(ivCiphertext_, key, iv_);
        //if(isValid(possiblePlaintext)) {
          //auto possiblePlaintext = decrypt(ciphertext_, key, iv_);
          if(isValid(possiblePlaintext))
          {
            std::cout
            << "FOUND! possiblePlaintext:'" << possiblePlaintext
            << "', fullKeyStr:'" << hex(key) << "'"
            << std::endl;
            insertKey(key);
            working_ = false;
          }
        //}
      }
      catch(...)
      {
      }
      addOnBit(key, suffixBitSize_, numOfThreads_);
    }
  }
  bool isValid(const std::string& possiblePlaintext)
  {
    //std::cout << "testing: '" << possiblePlaintext << "'" << std::endl;
    return std::all_of(std::begin(possiblePlaintext), std::end(possiblePlaintext), [](const auto& c) {
      //std::cout << "current: " << (int)c << " " << c << std::endl;
      return std::isgraph(c) || std::isspace(c);
    });
  }

  unsigned int keyLength_;
  unsigned int suffixLength_;
  Key suffixBuf_;
  unsigned suffixBitSize_;
  std::string suffix_;
  Iv iv_;
  std::mutex possibleKeyInsertionMutex_;
  Keys keys_;
  ByteBuffer ciphertext_;
  ByteBuffer ivCiphertext_;
  const uint64_t numOfThreads_;
  bool working_;

  std::atomic<int> lastPrint_;
  std::chrono::time_point<std::chrono::system_clock> previousPrintTime_;
};
