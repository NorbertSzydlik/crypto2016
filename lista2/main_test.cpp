#include <string>
#include <cassert>
#include "utils.hpp"
#include "Cracker.hpp"

void test_isEncryptDecryptValid()
{
  auto key = toBytes(boost::multiprecision::cpp_int("0xab1ded9cca17997a7956aec234a8ec2bbbedae026eb3465705c6c1c81075b917"), 32);
  auto iv = Iv({0x84, 0x8f, 0xa0, 0x62, 0x2a, 0xc8, 0x97, 0xa7, 0x81, 0xb1, 0xfa, 0xd6, 0xe6, 0xd6, 0xe2, 0x02});

  std::string plaintext = "test test dfkgjdfigjio jieog";
  auto cipherText = encrypt(plaintext, key, iv);
  auto plaintextAfterDecrypt = decrypt(cipherText, key, iv);
  assert(plaintext == plaintextAfterDecrypt);
}

void test_decrypt()
{
  ByteBuffer cipherText = {
    0b01010010, 0b00110000, 0b10110001, 0b11010100, 0b00001001, 0b10100010, 0b00110000, 0b01011101,
    0b11100111, 0b10110111, 0b10100111, 0b11010110, 0b00000110, 0b11111001, 0b11001101, 0b01110000,
    0b10000011, 0b00110001, 0b11100010, 0b01111100, 0b01001101, 0b10100010, 0b01100011, 0b01110100,
    0b00001101, 0b00101000, 0b00010111, 0b01011000, 0b00101101, 0b11100001, 0b11100000, 0b10010001,
    0b00111000, 0b00101110, 0b01100111, 0b10010111, 0b01010001, 0b01010000, 0b00110101, 0b10010100,
    0b10111100, 0b11011101, 0b01101101, 0b10000001, 0b10110110, 0b10110111, 0b10110111, 0b11000100,
    0b11010100, 0b11011010, 0b10111100, 0b11001101, 0b10000101, 0b00110111, 0b00011100, 0b10101110,
    0b11011100, 0b01111101, 0b00110010, 0b01001000, 0b10000010, 0b00111010, 0b01111000, 0b00011101,
    0b10010101, 0b01111101, 0b10111001, 0b11100101, 0b11100111, 0b00001111, 0b00011110, 0b10110110,
    0b00011001, 0b00011100, 0b10011111, 0b11000100, 0b10111111, 0b01111110, 0b01111010, 0b00110010,
    0b11010111, 0b01000101, 0b10110000, 0b01110110, 0b01110011, 0b10010001, 0b11110100, 0b11010000,
    0b01010101, 0b00011001, 0b01000110, 0b00111011, 0b01101001, 0b10001110, 0b11001010, 0b11011111,
    0b00010110, 0b01011100, 0b00100100, 0b10111001, 0b10000011, 0b01001111, 0b11010110, 0b10011000,
    0b11011000, 0b00100010, 0b01001111, 0b01100001, 0b00111111, 0b00110001, 0b10011110, 0b00111101
  };
  auto iv = Iv({0x06, 0x6b, 0x57, 0x5f, 0x98, 0xa2, 0x06, 0x5c, 0xa5, 0x13, 0x24, 0xdf, 0xf2, 0x2a, 0x98, 0x65 });

  auto key = Key({0x0f, 0x1d, 0xed, 0x9c, 0xca, 0x17, 0x99, 0x7a, 0x79, 0x56, 0xae, 0xc2, 0x34, 0xa8, 0xec, 0x2b
    , 0xbb, 0xed, 0xae, 0x02, 0x6e, 0xb3, 0x46, 0x57, 0x05, 0xc6, 0xc1, 0xc8, 0x10, 0x75, 0xb9, 0x17});

  auto plaintextAfterDecrypt = decrypt(cipherText, key, iv);
  std::cout << plaintextAfterDecrypt << std::endl;
}

void test_isCrackerValid()
{
  auto plainText = "test test";
  auto iv = Iv({0x06, 0x6b, 0x57, 0x5f, 0x98, 0xa2, 0x06, 0x5c, 0xa5, 0x13, 0x24, 0xdf, 0xf2, 0x2a, 0x98, 0x65 });
  auto key = Key({0x0f, 0x1d, 0xed, 0x9c, 0xca, 0x17
    , 0x99, 0x7a, 0x79, 0x56, 0xae, 0xc2, 0x34, 0xa8, 0xec, 0x2b, 0xbb, 0xed, 0xae, 0x02
    , 0x6e, 0xb3, 0x46, 0x57, 0x05, 0xc6, 0xc1, 0xc8, 0x10, 0x75, 0xb9, 0x17});
  std::string suffix = "1ded9cca17997a7956aec234a8ec2bbbedae026eb3465705c6c1c81075b917";

  auto cipherText = encrypt(plainText, key, iv);

  Cracker c(64, suffix, iv);
  auto keys = c.crack(cipherText);
  assert(keys.size() > 0);
  auto foundKey = keys[0];

  auto plaintextAfterDecrypt = decrypt(cipherText, foundKey, iv);
  assert(plainText == plaintextAfterDecrypt);
}

int main()
{
  test_isEncryptDecryptValid();
  test_decrypt();
  test_isCrackerValid();
}
