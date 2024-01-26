#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "../include/aes128.h"

//Written from 21.01.2024 to 26.01.2024 in about 500 lines of code

//Implementation of AES 128 in c using these Wikipedia links:
//https://en.wikipedia.org/wiki/Rijndael_MixColumns             26.01.2024
//https://de.wikipedia.org/wiki/Rijndael_MixColumns             26.01.2024
//https://en.wikipedia.org/wiki/Advanced_Encryption_Standard    26.01.2024
//https://en.wikipedia.org/wiki/Rijndael_S-box                  26.01.2024
//https://de.wikipedia.org/wiki/Advanced_Encryption_Standard    26.01.2024

int main(){

    //Deklaration and Initialization of a message and a user key
    unsigned char message[] = "AES";
    unsigned char key[16] = {
        1, 2, 3, 4, 
        5, 6, 7, 8, 
        9, 10, 11, 12, 
        13, 14, 15, 16
    };

    //Create a struct of type struct aes
    struct aes* aes = createAES(message, key);

    //store results of encryption and decryption
    unsigned char* cipher = aes_encrypt(aes);
    unsigned char* plaintext = aes_decrypt(aes);
    //free the memory to prevent memory leaks
    free(cipher);
    free(plaintext);
    FILE* fp = aes_encrypt_file(aes, "C:/Users/Max/Desktop/AES/source/test.txt");
    FILE* fp0 = aes_decrypt_file(aes, "C:/Users/Max/Desktop/AES/source/test.txt", "C:/Users/Max/Desktop/AES/source/test1.txt");
    

    //Encrypting and decrypting File contents
    
    //free memory
    destroyAES(aes);

    return 0;
}