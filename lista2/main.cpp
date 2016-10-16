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
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/format.hpp>

namespace mp = boost::multiprecision;
using ByteBuffer = std::vector<uint8_t>;
using Key = mp::uint256_t;
using Iv = mp::uint128_t;
const auto AES_BITS = 256;

class CipherCtxHandler
{
public:
    CipherCtxHandler() : ctx_(EVP_CIPHER_CTX_new()) 
    {
        if(!ctx_)
            std::cerr << "CTX initailization failed" << std::endl;
    }
    ~CipherCtxHandler() 
    {
        EVP_CIPHER_CTX_free(ctx_);
    }
    EVP_CIPHER_CTX* operator&()
    {
        return ctx_;
    }
private:
    EVP_CIPHER_CTX* ctx_;
};

std::string hex(const ByteBuffer& b)
{
    std::ostringstream oss;
    for(const auto& c : b)
    {
        oss << std::setfill('0');
        oss << std::setw(2);
        oss << std::hex << static_cast<int>(c) << " ";
    }
    return oss.str();

}

ByteBuffer toBytes(const mp::cpp_int num, std::size_t desiredSize)
{
    ByteBuffer numBuff(desiredSize, 0);
    mp::export_bits(num, std::rbegin(numBuff), 8, false);
    //std::cout << "exported: " << (numBuff.size() * 8) << " bits, " << hex(numBuff) << std::endl;
    return numBuff;
}

ByteBuffer encrypt(const std::string& plaintextStr, const Key& keyNum, const Iv& ivNum)
{
    const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    ByteBuffer plaintext;
    std::copy(std::begin(plaintextStr), std::end(plaintextStr), std::back_inserter(plaintext));
    auto key = toBytes(keyNum, AES_BITS / 8); 
    auto iv = toBytes(ivNum, AES_BITS / 16);   
 
    ByteBuffer ciphertext(plaintext.size() + blockSize);

    CipherCtxHandler ctx;

    int len;

    int ciphertext_len;

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
        throw std::runtime_error("encrypt failed ctx init");

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(&ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
        throw std::runtime_error("encrypt failed encrypt update");
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(&ctx, ciphertext.data() + len, &len)) throw std::runtime_error("encrypt failed encrypt final");
    ciphertext_len += len;
   
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::string decrypt(const ByteBuffer& ciphertext, const Key& keyNum, const Iv& ivNum)
{
    CipherCtxHandler ctx;
   
    auto key = toBytes(keyNum, AES_BITS / 8);
    auto iv = toBytes(ivNum, AES_BITS / 16);
  
    ByteBuffer plaintext(ciphertext.size(), 0);
    int len;
    int plaintext_len;

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
        throw std::runtime_error("decrypt Failed init");

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(&ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
        throw std::runtime_error("decrypt Failed update");
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(&ctx, plaintext.data() + len, &len)) throw std::runtime_error("decrypt Failed final");
        plaintext_len += len;

    plaintext.resize(plaintext_len);
    
    std::string plaintextStr;
    std::copy(std::begin(plaintext), std::end(plaintext), std::back_inserter(plaintextStr));
    return plaintextStr;
}

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
           using Dec = mp::number<mp::cpp_dec_float<0> >;
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
        mp::export_bits(suffix_, std::back_inserter(b), 8);
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
    Cracker c(16, Key("0xaa56b18f"), Iv("0x4ef619fdd4cda8a7a752851953264200"));
    auto keys = c.crack(cryptogram);
    for(auto& k : keys)
    {
        std::cout << std::hex << k << std::endl;
    }
}

int main()
{
    task1();
}
