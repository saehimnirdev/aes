#ifndef AES128_ENCRYPTOR_H
    #define AES128_ENCRYPTOR_H
    #define BLOCK_SIZE 16
    #define ROUNDS 10

    #include "malloc.h"

    #include "s_box.h"
    #include "utils.h"

    typedef unsigned char byte;

    struct aes128_encryptor{
        byte* data;
        byte* userkey;
        byte* expandedKey;
        byte* roundkey;
    };

    struct aes128_encryptor* createAESEncryptor(byte* data, byte* userkey);
    byte* encrypt(struct aes128_encryptor* encryptor);

    byte expandKey(struct aes128_encryptor* encryptor, byte i);
    byte addRoundKey(struct aes128_encryptor* encryptor);
    byte substituteBytes(struct aes128_encryptor* encryptor);
    byte shiftRows(struct aes128_encryptor* encryptor);
    byte mixColumns(struct aes128_encryptor* encryptor);

    byte xtimes(byte x);

    void rotateWord(byte* word);
    void substituteWord(byte* word);

    byte* addPadding(byte* str);
    struct message* format(byte* data);
    byte* spliteBytes(byte* str, int from, int to);

#endif