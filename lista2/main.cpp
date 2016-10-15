#include <sstream>
#include <iostream>
#include <iomanip>
#include <array>
#include <vector>
#include <mutex>
#include <thread>
#include <cstdint>
#include <cassert>
#include <memory>
#include <iterator>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <boost/multiprecision/cpp_int.hpp>

namespace mp = boost::multiprecision;
using ByteBuffer = std::vector<uint8_t>;
using Key = mp::uint256_t;
using Iv = mp::uint256_t;
const auto AES_BITS = 256;


std::string hex(const ByteBuffer& b)
{
    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0');
    for(const auto& c : b)
    {
        oss << std::hex << static_cast<int>(c) << " ";
    }
    return oss.str();

}
std::string hex(const mp::uint256_t& n)
{
    std::ostringstream oss;
    oss << std::setw(AES_BITS/8);
    oss << std::setfill('0');
    oss << n;
    return oss.str();
}

ByteBuffer encrypt(const std::string& data, const Key& key, const Iv& iv)
{
    EVP_CIPHER_CTX ctx;
    ByteBuffer keyBuff;
    mp::export_bits(key, std::back_inserter(keyBuff), 8);
    
    ByteBuffer ivBuff;
    mp::export_bits(iv, std::back_inserter(ivBuff), 8);

    EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), keyBuff.data(), ivBuff.data());
    int outDataLen = data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());

    ByteBuffer outData(outDataLen, 0);
    EVP_EncryptFinal(&ctx, outData.data(), &outDataLen);

    outData.resize(outDataLen);
    return outData;
}

std::string decrypt(const ByteBuffer& data, const Key& key, const Iv& iv)
{
    EVP_CIPHER_CTX ctx;
    ByteBuffer keyBuff;
    mp::export_bits(key, std::back_inserter(keyBuff), 8);
    
    ByteBuffer ivBuff;
    mp::export_bits(iv, std::back_inserter(ivBuff), 8);

    EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), keyBuff.data(), ivBuff.data());
    int outDataLen = data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());

    std::string outData(outDataLen + 1, 0);
    EVP_DecryptFinal(&ctx, reinterpret_cast<uint8_t*>(&outData[0]), &outDataLen);

    outData.resize(outDataLen);
    return outData;
}

class Cracker
{
using Keys = std::vector<Key>;
public:
    Cracker(unsigned int keyLength, const Key& k2, const Iv& iv) :
        keyLength_(keyLength),
        k2_(k2),
        iv_(iv),
        numOfThreads_(std::thread::hardware_concurrency())
    {}

    Keys crack(const ByteBuffer& cryptogram)
    {
        keys_ = {};
        
        std::cout << "Cracking using " << numOfThreads_ << "threads" << std::endl; 
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
    }
    
    unsigned int keyLength_;
    Key k2_;
    Iv iv_;
    std::mutex possibleKeyInsertionMutex_;
    Keys keys_;
    const uint64_t numOfThreads_;
};

void task1()
{
    ByteBuffer cryptogram {
        0b01000010, 0b01011000, 0b00011011, 0b01100011, 
        0b01101101, 0b01001000, 0b10101001, 0b01101101, 
        0b10101111, 0b01011001, 0b00100101, 0b10010011, 
        0b11001001, 0b10011010, 0b00000001, 0b10001001, 
        0b00001000, 0b01001000, 0b10001111, 0b11111110, 
        0b01101101, 0b10011111, 0b10110110, 0b01000100, 
        0b00110101, 0b10011111, 0b01100100, 0b10101000, 
        0b00010011, 0b00111100, 0b11110001, 0b10101011, 
        0b01100011, 0b11011110, 0b00010010, 0b00001010, 
        0b00001011, 0b01100010, 0b10010111, 0b11011100, 
        0b00110011, 0b01101101, 0b00001111, 0b01001101, 
        0b11101110, 0b01110000, 0b01011101, 0b10011010, 
        0b00101100, 0b01000111, 0b00101110, 0b11111101, 
        0b11110100, 0b11000111, 0b00111101, 0b01101000, 
        0b11000100, 0b00110001, 0b10100001, 0b10010110, 
        0b01010101, 0b01111101, 0b11000000, 0b11101001,
        0b11110100, 0b10111001, 0b00101010, 0b10001010, 
        0b01100101, 0b10100100, 0b11110000, 0b00100110, 
        0b00110000, 0b00011101, 0b10011011, 0b11000011, 
        0b00100011, 0b10110101, 0b10110010, 0b00000111, 
        0b11101011, 0b10011100, 0b00100100, 0b01100000, 
        0b00111101, 0b00111010, 0b10110000, 0b01100111, 
        0b11101111, 0b11111101, 0b00011100, 0b11101110, 
        0b00111110, 0b00110011, 0b01000101, 0b00100100, 
        0b01111010, 0b00010001, 0b01011111, 0b01011100,
        0b11000100, 0b00010010, 0b11111101, 0b11010001, 
        0b10111111, 0b01101100, 0b10010001, 0b11010110,
        0b00010111, 0b01010111, 0b00010100, 0b11110111,
        0b00011101, 0b00000100, 0b01110111, 0b11001100,
        0b00110001, 0b11000010, 0b11111101, 0b00001000,
        0b01001101, 0b00001101, 0b10001000, 0b11110011,
        0b11101101, 0b11000100, 0b00100111, 0b00000010,
        0b01110101, 0b11011100, 0b00000100, 0b01101000,
        0b00010000, 0b11110100, 0b01011100, 0b11010010,
        0b01110001, 0b10001100, 0b00011110, 0b00101010,
        0b00110101, 0b10111000, 0b11010101, 0b10001101,
        0b11100011, 0b11011111, 0b00101010, 0b10100100,
        0b10010010, 0b10100000, 0b00000011, 0b00111110,
        0b01111011, 0b10011011, 0b11000100, 0b00111001,
        0b11001101, 0b11010110, 0b01110110, 0b01100111
    };
}

int main()
{
    Key ckey = 0;
    Iv ivec = 0;
    
    auto crypto = encrypt("test encrypt", ckey, ivec);
    
    std::cout << hex(crypto) << std::endl;

}
