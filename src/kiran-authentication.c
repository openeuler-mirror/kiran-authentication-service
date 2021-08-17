#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "authentication_i.h"

#define KEY_LEN 2048
#define RSA_BUFFER_LEN 4096

RSA *create_RSA(unsigned char * key,
		int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;

    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        return NULL;
    }

    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    return rsa;
}

int kiran_authentication_rsa_public_encrypt(char *data,
                                            int data_len,
                                            unsigned char *key,
                                            unsigned char **encrypted)
{
    RSA * rsa = NULL;
    unsigned char buf[RSA_BUFFER_LEN] = {0};
    unsigned char *ptr = NULL;
    int result = -1;
    
    rsa = create_RSA(key, 1);
    if (rsa == NULL)
    {
	return -1;
    }

    result = RSA_public_encrypt(data_len, data, buf, rsa, RSA_PKCS1_PADDING);
    if (result > 0)
    {
        ptr = malloc(result);
        if (ptr)
        {
            memcpy(ptr, buf, result);
        }
    }

    *encrypted = ptr;

    return result;
}

int kiran_authentication_rsa_private_decrypt(unsigned char *enc_data,
                                             int data_len,
                                             unsigned char *key,
                                             char **decrypted)
{
    RSA *rsa = NULL;
    unsigned char buf[RSA_BUFFER_LEN] = {0};
    unsigned char *ptr = NULL;
    int result = -1;
    
    rsa = create_RSA(key, 0);
    if (rsa == NULL)
    {
	return -1;
    }

    result = RSA_private_decrypt(data_len, enc_data, buf, rsa, RSA_PKCS1_PADDING);
    if (result > 0)
    {
        ptr = malloc(result);
        if (ptr)
        {
            memcpy(ptr, buf, result);
        }
    }

    *decrypted = ptr;

    return result;
}

int
kiran_authentication_rsa_key_gen(char **public_key, char **private_key)
{
    EVP_PKEY_CTX *evp_ctx = NULL;
    EVP_PKEY  *ppkey  = NULL;
    BIO *bio = NULL;
    BUF_MEM *pub_buf = NULL;
    BUF_MEM *pri_buf = NULL;

    *private_key = NULL;
    *public_key = NULL;

    evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (evp_ctx == NULL)
    {
	return -1;
    }

    EVP_PKEY_keygen_init(evp_ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, KEY_LEN);

    EVP_PKEY_keygen(evp_ctx, &ppkey);
    if (ppkey == NULL)
    {
        EVP_PKEY_CTX_free(evp_ctx);
	return -1;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        PEM_write_bio_PUBKEY(bio, ppkey);
        BIO_get_mem_ptr(bio, &pub_buf);
        if (pub_buf)
        {
            *public_key = strdup(pub_buf->data);
        }
        BIO_free(bio);
    }

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        PEM_write_bio_PrivateKey(bio, ppkey, NULL, NULL, 0, 0, NULL);
        BIO_get_mem_ptr(bio, &pri_buf);
        if (&pri_buf)
        {
            *private_key = strdup(pub_buf->data);
        }
        BIO_free(bio);
    }

    EVP_PKEY_free(ppkey);
    EVP_PKEY_CTX_free(evp_ctx);

    if (*public_key == NULL ||
        *private_key == NULL)
    {
        if (*public_key)
        {
            free(*public_key);
            *public_key = NULL;
        }

        if (*private_key)
        {
            free(*private_key);
            *private_key = NULL;
        }

        return -1;
    }

    return 0;
}
