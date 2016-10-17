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
        std::cout <<
            (boost::format("Suffix: '%1%', keyLength: %2%, suffixSize: %3%")
                % suffix
                % keyLength
                % suffix.size()
            ) << std::endl;
        assert(suffix.size() < keyLength);
        suffixNum_ = Key(numberFromBytes(std::begin(suffix), std::end(suffix)));
        std::cout << "KeyLength=" << keyLength << std::endl;
        maxKey_ = std::string(keyLength - suffix.size(), 'f') + suffix_;
        std::cout << "maxKey:" << maxKey_ << std::endl;
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
        std::string prefixHex = (boost::format("%1$p") % prefix).str();
        auto keyHex = prefixHex + suffix_;
        assert(keyHex.size() == keyLength_);

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
       while(fullKeyStr <= maxKey_)
       {
           assert(fullKeyStr.size() <= keyLength_);
           auto fullKey = Key(numberFromBytes(std::begin(fullKeyStr), std::end(fullKeyStr)));
           std::cout << "trying key: " << fullKeyStr << std::endl;
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
           prefix += numOfThreads_;
           fullKeyStr = getFullKeyStr(prefix);

           std::cout << "key:" << fullKeyStr << " maxKey:" << maxKey_ << std::endl;
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
