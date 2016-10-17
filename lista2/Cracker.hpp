#include <thread>
#include <mutex>
#include <memory>
#include <iterator>
#include <string>
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
        suffixNum_ = Key(numberFromBytes(std::begin(suffix), std::end(suffix)));
        auto maxKeyStr = std::string('f', keyLength);
        maxKey_ = Key(numberFromBytes(std::begin(maxKeyStr), std::end(maxKeyStr)));
    }

    Keys crack(const ByteBuffer& ciphertext)
    {
        const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        ciphertext_ = ciphertext;
        std::copy(std::begin(ciphertext_), std::begin(ciphertext_) + blockSize, std::back_inserter(ivCiphertext_));
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
    Key getFullKey(const Key& prefix)
    {
        auto key = (prefix << (suffix_.size() * 4)) + suffixNum_;
        auto keyHex = hex(toBytes(key, AES_BITS), false);
        return Key(numberFromBytes(std::begin(keyHex), std::end(keyHex)));
    }
    void crackThread(int s)
    {
       for(Key prefix = s; prefix < maxKey_; prefix += numOfThreads_)
       {
           Key fullKey = getFullKey(prefix);
           using Dec = boost::multiprecision::number<boost::multiprecision::cpp_dec_float<0> >;
           if(prefix % 0x010000 == 0)
               std::cout << boost::format("progress: %1$8.5f%%") % ((fullKey.convert_to<Dec>() / maxKey_.convert_to<Dec>()) * 100.0) << std::endl;
           //std::cout << "trying key: " << std::hex << fullKey << std::endl;
           try
           {
               auto possiblePlaintext = decrypt(ivCiphertext_, fullKey, iv_);
               if(!isValid(possiblePlaintext))
                   continue;
               std::cout << boost::format("FOUND! key:%1$x, plaintext:%2$s") % fullKey % possiblePlaintext << std::endl;
               insertKey(fullKey);
           }
           catch(...)
           {
           }
       }
    }
    bool isValid(const std::string& possiblePlaintext)
    {
        return std::all_of(std::begin(possiblePlaintext), std::end(possiblePlaintext), [](const auto& c) {
            return c >= 32 && c <= 126;
        });
    }

    unsigned int keyLength_;
    unsigned int suffixLength_;
    std::string suffix_;
    Key suffixNum_;
    Key maxKey_;
    Iv iv_;
    std::mutex possibleKeyInsertionMutex_;
    Keys keys_;
    ByteBuffer ciphertext_;
    ByteBuffer ivCiphertext_;
    const uint64_t numOfThreads_;
};
