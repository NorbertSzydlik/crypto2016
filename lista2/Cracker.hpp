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
        numOfThreads_(std::thread::hardware_concurrency())
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
        auto keyHex = prefixHex + suffix_;
        std::transform(std::begin(keyHex), std::end(keyHex), std::begin(keyHex), ::tolower);

        return keyHex;
    }
    Key getFullKey(const Key& prefix)
    {
        const auto keyHex = getFullKeyStr(prefix);
        return Key(numberFromBytes(std::begin(keyHex), std::end(keyHex)));
    }
    void crackThread(int s)
    {
       Key prefix = s;
       auto fullKeyStr = getFullKeyStr(prefix);
       while(fullKeyStr.size() <= keyLength_)
       {
           auto fullKey = Key(numberFromBytes(std::begin(fullKeyStr), std::end(fullKeyStr)));
           try
           {
               auto possiblePlaintext = decrypt(ivCiphertext_, fullKey, iv_);
               if(!isValid(possiblePlaintext))
                   continue;
               std::cout
                   << "FOUND! possiblePlaintext:'" << possiblePlaintext
                   << "', fullKeyStr:'" << fullKeyStr << "'"
                   << std::endl; 
               insertKey(fullKey);
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
        return std::all_of(std::begin(possiblePlaintext), std::end(possiblePlaintext), [](const auto& c) {
            return c >= 32 && c <= 126;
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
