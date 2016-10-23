#include <thread>
#include <mutex>
#include <memory>
#include <iterator>
#include <string>
#include <algorithm>
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
        numOfThreads_(1)//std::thread::hardware_concurrency())
    {
        assert(suffix.size() < keyLength);
        suffixNum_ = Key(numberFromBytes(std::begin(suffix), std::end(suffix)));
        maxKey_ = std::string(keyLength - suffix.size(), 'f') + suffix_;
        assert(maxKey_.size() == keyLength);
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
    std::string getFullKeyStr(const Key& prefix)
    {
        std::string prefixHex = (boost::format("%1$x") % prefix).str();
        auto zeroesNeeded = (int)keyLength_ - (int)prefixHex.size() - (int)suffix_.size();
        std::string zeroes = zeroesNeeded > 0 ? std::string(zeroesNeeded, '0') : "";
        auto keyHex = zeroes + prefixHex + suffix_;
        std::transform(std::begin(keyHex), std::end(keyHex), std::begin(keyHex), ::tolower);

        return keyHex;
    }
    Key getFullKey(const Key& prefix)
    {
        const auto keyHex = getFullKeyStr(prefix);
        return Key("0x" + keyHex);
    }
    void crackThread(int s)
    {
       Key prefix = s;
       auto fullKeyStr = getFullKeyStr(prefix);
       while(fullKeyStr.size() <= keyLength_)
       {
           auto fullKey = getFullKey(prefix);
           if(prefix % (1024 * 8) == 0) std::cout << "current key:'" << fullKeyStr << "'" << std::endl;
           try
           {
               auto possiblePlaintext = decrypt(ciphertext_, fullKey, iv_);
               if(isValid(possiblePlaintext)) {
                   std::cout
                       << "FOUND! possiblePlaintext:'" << possiblePlaintext
                       << "', fullKeyStr:'" << fullKeyStr << "'"
                       << std::endl;
                   insertKey(fullKey);
               }
           }
           catch(...)
           {
           }
           prefix += numOfThreads_;
           fullKeyStr = getFullKeyStr(prefix);
       }
    }
    bool isValid(const std::string& possiblePlaintext)
    {
        //std::cout << "testing: '" << possiblePlaintext << "'" << std::endl;
        return std::all_of(std::begin(possiblePlaintext), std::end(possiblePlaintext), [](const auto& c) {
            //std::cout << "current: " << (int)c << " " << c << std::endl;
            return (c >= 32 && c <= 126) || c == 10 || c == 13 || c == 0;
        });
    }

    unsigned int keyLength_;
    unsigned int suffixLength_;
    std::string suffix_;
    Key suffixNum_;
    std::string maxKey_;
    Iv iv_;
    std::mutex possibleKeyInsertionMutex_;
    Keys keys_;
    ByteBuffer ciphertext_;
    ByteBuffer ivCiphertext_;
    const uint64_t numOfThreads_;
};
