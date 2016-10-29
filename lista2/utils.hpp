#pragma once
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "CipherCtxHandler.hpp"

using ByteBuffer = std::vector<uint8_t>;
using Key = ByteBuffer;
using Iv = ByteBuffer;
const auto AES_BITS = 256;

void addOnByte(ByteBuffer& buf, int byte, int value)
{
  if(value == 0) return;
  if(buf.size() <= byte)
  {
    buf.resize(byte + 1);
  }
  auto currentByte = (std::rbegin(buf) + byte);
  uint32_t newValue = *currentByte + value;
  *currentByte = newValue % 256;
  addOnByte(buf, byte + 1, newValue / 256);
}
void addOnBit(ByteBuffer& buf, int bit, int value)
{
  addOnByte(buf, bit / 8, value << (bit % 8));
}

std::string hex(const ByteBuffer& b, bool splitWithSpaces)
{
    std::ostringstream oss;
    for(const auto& c : b)
    {
        oss << std::setfill('0');
        oss << std::setw(2);
        oss << std::hex << static_cast<int>(c) << (splitWithSpaces ? " " : "");
    }
    return oss.str();
}
std::string hex(const ByteBuffer& b)
{
    return hex(b, true);
}

ByteBuffer toBytes(const boost::multiprecision::cpp_int num, std::size_t desiredSize)
{
    ByteBuffer numBuff(desiredSize, 0);
    boost::multiprecision::export_bits(num, std::rbegin(numBuff), 8, false);
    //std::cout << "exported: " << (numBuff.size() * 8) << " bits, " << hex(numBuff) << std::endl;
    return numBuff;
}
template <class ForwardIterator>
boost::multiprecision::cpp_int numberFromBytes(const ForwardIterator& begin, const ForwardIterator& end)
{
    boost::multiprecision::cpp_int num;
    boost::multiprecision::import_bits(num, begin, end, 8);
    return num;
}

ByteBuffer encrypt(const std::string& plaintextStr, const Key& key, const Iv& iv)
{
    const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    ByteBuffer plaintext;
    std::copy(std::begin(plaintextStr), std::end(plaintextStr), std::back_inserter(plaintext));

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

std::string decrypt(const ByteBuffer& ciphertext, const Key& key, const Iv& iv)
{
    CipherCtxHandler ctx;

    ByteBuffer plaintext(ciphertext.size(), 0);
    int len;
    int plaintext_len;

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
    {
        throw std::runtime_error("decrypt Failed init");
    }
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(&ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
    {
        throw std::runtime_error("decrypt Failed update");
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(&ctx, plaintext.data() + len, &len))
    {
        throw std::runtime_error("decrypt Failed final");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);

    std::string plaintextStr;
    std::copy(std::begin(plaintext), std::end(plaintext), std::back_inserter(plaintextStr));
    return plaintextStr;
}
