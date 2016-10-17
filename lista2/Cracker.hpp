#include <thread>
#include <mutex>
#include <memory>
#include <iterator>
#include <boost/format.hpp>
#include "utils.hpp"

class Cracker
{
using Keys = std::vector<Key>;
public:
    Cracker(unsigned int keyLength, const Key& suffix, const Iv& iv) :
        keyLength_(keyLength),
        suffix_(suffix),
        iv_(iv),
        numOfThreads_(std::thread::hardware_concurrency())
    {
        suffixLength_ = lengthOfKey(suffix_);
        maxKey_ = (Key(1) << (keyLength_ * 4 + 1)) - 1;
    }

    Keys crack(const ByteBuffer& cryptogram)
    {
        const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        cryptogram_ = cryptogram;
        std::copy(std::begin(cryptogram_), std::begin(cryptogram_) + blockSize, std::back_inserter(shortCryptogram_));
        keys_ = {};

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
    void crackThread(int s)
    {
       for(Key prefix = s; prefix < maxKey_; prefix += numOfThreads_)
       {
           Key fullKey = (prefix << (suffixLength_ * 8)) + suffix_;
           using Dec = boost::multiprecision::number<boost::multiprecision::cpp_dec_float<0> >;
           if(prefix % 0x010000 == 0)
               std::cout << boost::format("progress: %1$8.5f%%") % ((fullKey.convert_to<Dec>() / maxKey_.convert_to<Dec>()) * 100.0) << std::endl;
           //std::cout << "trying key: " << std::hex << fullKey << std::endl;
           try
           {
               auto possiblePlaintext = decrypt(shortCryptogram_, fullKey, iv_);
               if(!isValid(possiblePlaintext))
                   continue;

               possiblePlaintext = decrypt(cryptogram_, fullKey, iv_);
               if(isValid(possiblePlaintext))
               {
                   std::cout << boost::format("FOUND! key:%1$x, plaintext:%2$s") % fullKey % possiblePlaintext << std::endl;
                   insertKey(fullKey);
               }
           }
           catch(...)
           {
           }
       }
    }
    unsigned int lengthOfKey(const Key& key)
    {
        ByteBuffer b;
        boost::multiprecision::export_bits(suffix_, std::back_inserter(b), 8);
        return b.size();
    }
    bool isValid(const std::string& possiblePlaintext)
    {
        return std::all_of(std::begin(possiblePlaintext), std::end(possiblePlaintext), [](const auto& c) {
            return c >= 32 && c <= 126;
        });
    }

    unsigned int keyLength_;
    unsigned int suffixLength_;
    Key suffix_;
    Key maxKey_;
    Iv iv_;
    std::mutex possibleKeyInsertionMutex_;
    Keys keys_;
    ByteBuffer cryptogram_;
    ByteBuffer shortCryptogram_;
    const uint64_t numOfThreads_;
};
