#include <string>
#include <cassert>
#include "utils.hpp"
#include "Cracker.hpp"

void test_isEncryptDecryptValid()
{
  auto key = toBytes(boost::multiprecision::cpp_int("0xab1ded9cca17997a7956aec234a8ec2bbbedae026eb3465705c6c1c81075b917"), 32);
  auto iv = Iv({0x84, 0x8f, 0xa0, 0x62, 0x2a, 0xc8, 0x97, 0xa7, 0x81, 0xb1, 0xfa, 0xd6, 0xe6, 0xd6, 0xe2, 0x02});

  std::string plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur non bibendum quam. Donec nec leo mauris. Pellentesque accumsan mauris at ornare iaculis. Curabitur non massa sit amet mi fringilla dapibus vel sit amet ex. Mauris eleifend dictum mattis. Vestibulum quis tristique mauris. Sed metus sem, varius non elit sit amet, mattis auctor ipsum. Quisque interdum venenatis ex ut condimentum. Proin enim ligula, blandit lacinia lacus ac, porttitor faucibus dolor. Praesent condimentum felis vel porta tristique.Nulla vel velit id velit maximus bibendum. Proin maximus, erat eget tincidunt dictum, tortor arcu ultrices leo, quis suscipit urna neque ac ante. Maecenas bibendum maximus risus vitae venenatis. Pellentesque sed molestie dolor, sed rhoncus enim. Aenean commodo scelerisque lectus vitae placerat. Etiam dictum semper facilisis. Cras egestas ligula sapien, nec tristique neque consectetur in. Etiam hendrerit et nibh id aliquam. Donec consequat enim auctor sodales venenatis. Praesent bibendum, nunc vitae convallis posuere, urna mauris laoreet elit, eu placerat nulla ligula sed lacus.Phasellus eu justo lacinia, dictum odio vitae, egestas nisi. Mauris molestie, velit eu euismod lobortis, quam erat volutpat urna, cursus tincidunt enim purus id nisl. Phasellus semper elit sit amet hendrerit consectetur. Vestibulum sit amet scelerisque diam. Aliquam ut dui lacus. Etiam vulputate risus vitae ligula tincidunt faucibus sed eu leo. Aenean ac enim lectus. Duis a diam sit amet turpis facilisis vulputate sit amet eu massa. Ut ac nibh maximus, euismod lacus in, auctor nisi. Etiam tempus est arcu, in molestie arcu tempor eget. Praesent semper lectus eu lobortis vestibulum. Fusce ac ornare arcu. Sed dolor justo, lacinia ut orci non, condimentum commodo eros. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Integer consequat nisi velit, in dignissim velit porta vitae.Pellentesque libero nulla, facilisis sed massa vitae, pellentesque tincidunt odio. Aenean sodales nunc justo, id tincidunt mi pulvinar sed. Nullam enim est, tempus quis velit in, semper euismod turpis. Aliquam a massa justo. Duis hendrerit convallis nulla, ac lacinia sem tristique eget. Maecenas scelerisque neque sed est semper porta. Morbi vehicula elit sed tellus condimentum gravida. Nam quis erat augue. Sed a placerat ante, in vulputate tortor. Mauris mauris orci, rutrum nec est ut, sagittis pulvinar mauris. Aliquam ipsum dolor, bibendum vitae augue ac, iaculis accumsan nisi.";
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
  std::string plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur non bibendum quam. Donec nec leo mauris. Pellentesque accumsan mauris at ornare iaculis. Curabitur non massa sit amet mi fringilla dapibus vel sit amet ex. Mauris eleifend dictum mattis. Vestibulum quis tristique mauris. Sed metus sem, varius non elit sit amet, mattis auctor ipsum. Quisque interdum venenatis ex ut condimentum. Proin enim ligula, blandit lacinia lacus ac, porttitor faucibus dolor. Praesent condimentum felis vel porta tristique.Nulla vel velit id velit maximus bibendum. Proin maximus, erat eget tincidunt dictum, tortor arcu ultrices leo, quis suscipit urna neque ac ante. Maecenas bibendum maximus risus vitae venenatis. Pellentesque sed molestie dolor, sed rhoncus enim. Aenean commodo scelerisque lectus vitae placerat. Etiam dictum semper facilisis. Cras egestas ligula sapien, nec tristique neque consectetur in. Etiam hendrerit et nibh id aliquam. Donec consequat enim auctor sodales venenatis. Praesent bibendum, nunc vitae convallis posuere, urna mauris laoreet elit, eu placerat nulla ligula sed lacus.Phasellus eu justo lacinia, dictum odio vitae, egestas nisi. Mauris molestie, velit eu euismod lobortis, quam erat volutpat urna, cursus tincidunt enim purus id nisl. Phasellus semper elit sit amet hendrerit consectetur. Vestibulum sit amet scelerisque diam. Aliquam ut dui lacus. Etiam vulputate risus vitae ligula tincidunt faucibus sed eu leo. Aenean ac enim lectus. Duis a diam sit amet turpis facilisis vulputate sit amet eu massa. Ut ac nibh maximus, euismod lacus in, auctor nisi. Etiam tempus est arcu, in molestie arcu tempor eget. Praesent semper lectus eu lobortis vestibulum. Fusce ac ornare arcu. Sed dolor justo, lacinia ut orci non, condimentum commodo eros. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Integer consequat nisi velit, in dignissim velit porta vitae.Pellentesque libero nulla, facilisis sed massa vitae, pellentesque tincidunt odio. Aenean sodales nunc justo, id tincidunt mi pulvinar sed. Nullam enim est, tempus quis velit in, semper euismod turpis. Aliquam a massa justo. Duis hendrerit convallis nulla, ac lacinia sem tristique eget. Maecenas scelerisque neque sed est semper porta. Morbi vehicula elit sed tellus condimentum gravida. Nam quis erat augue. Sed a placerat ante, in vulputate tortor. Mauris mauris orci, rutrum nec est ut, sagittis pulvinar mauris. Aliquam ipsum dolor, bibendum vitae augue ac, iaculis accumsan nisi.";
  //std::string plainText = "test";
  auto iv = Iv({0x06, 0x6b, 0x57, 0x5f, 0x98, 0xa2, 0x06, 0x5c, 0xa5, 0x13, 0x24, 0xdf, 0xf2, 0x2a, 0x98, 0x65 });
  auto key = Key({0x0f, 0x1d, 0xed, 0x9c, 0xca, 0x17
    , 0x99, 0x7a, 0x79, 0x56, 0xae, 0xc2, 0x34, 0xa8, 0xec, 0x2b, 0xbb, 0xed, 0xae, 0x02
    , 0x6e, 0xb3, 0x46, 0x57, 0x05, 0xc6, 0xc1, 0xc8, 0x10, 0x75, 0xb9, 0x17});
  std::string suffix = hex(key, false).substr(2, std::string::npos);

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
