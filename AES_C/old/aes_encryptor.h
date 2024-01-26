#ifndef AES_ENCRYPTOR_H
    #define AES_ENCRYPTOR_H
    #define AES_TRUE 0
    #define AES_FALSE 1
    #define AES_COLOR_ERROR "[ERROR]:\x1b[31m"
    #define AES_COLOR_WARNING "[WARNING]:\x1b[33m"
    #define AES_COLOR_OK "[OK]:\x1b[32m"
    #define AES_COLOR_DATA "\x1b[34m"
    #define AES_COLOR_CLEAR "\x1b[0m"
    typedef unsigned char byte;
    typedef unsigned char bool;

    #include <stdio.h>
    #include <malloc.h>
    #include <string.h>

    struct data_block{

        int size;
        byte** data;
    };

    struct aes_encryptor{

        struct data_block* data;
        struct data_block* key;
    };

    byte* aes_encrypt(byte* data, byte* key);
    
    struct data_block* format(byte* data);
    byte* splitBytes(byte* data, int from, int to);
    byte* addPadding(byte* data);

    byte log_to_console(char* color, char* message);


    #ifdef AES_128
        #define ROUNDS 10
        #define BLOCK_SIZE 16
    #elif defined AES_256
        #define ROUNDS 14
        #define BLOCK_SIZE 32
    #endif
#endif