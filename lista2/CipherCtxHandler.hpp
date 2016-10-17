#pragma once
#include <openssl/evp.h>

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
