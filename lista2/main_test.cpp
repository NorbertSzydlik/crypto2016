#include <string>
#include <cassert>
#include "utils.hpp"
#include "Cracker.hpp"

void test_isCrackerValid()
{
    std::string keyStr = "f123456789";
    std::string keySuffixStr(keyStr.size() - 1, 0);
    std::copy(std::begin(keyStr) + 1, std::end(keyStr), std::begin(keySuffixStr));

    auto key = Key(numberFromBytes(std::begin(keyStr), std::end(keyStr)));
    auto iv = Iv("0x4ef619fdd4cda8a7a752851953264200");
    std::string plaintext = "TEXT TO ENCRYPT";
    auto ciphertext = encrypt(plaintext, key, iv);
    Cracker c(keyStr.size(), keySuffixStr, iv);

    auto possibleKeys = c.crack(ciphertext);
    assert(possibleKeys.size() > 0);
    auto decrypted = decrypt(ciphertext, possibleKeys[0], iv);
    assert(plaintext == decrypted);
}

int main()
{
  test_isCrackerValid();
}
