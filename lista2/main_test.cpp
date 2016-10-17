#include <string>
#include <cassert>
#include "utils.hpp"
#include "Cracker.hpp"

void test_isCrackerValid()
{
    ByteBuffer keyBuff{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    auto key = Key(numberFromBytes(std::begin(keyBuff), std::end(keyBuff)));
    auto keySuffix = Key(numberFromBytes(std::begin(keyBuff) + 1, std::end(keyBuff)));
    auto iv = Iv("0x4ef619fdd4cda8a7a752851953264200");
    std::string plaintext = "TEXT TO ENCRYPT";
    auto ciphertext = encrypt(plaintext, key, iv);
    Cracker c(keyBuff.size(), keySuffix, iv);

    auto possibleKeys = c.crack(ciphertext);
    auto decrypted = decrypt(ciphertext, possibleKeys[0], iv);
    assert(plaintext == decrypted);
}

int main()
{
  test_isCrackerValid();
}
