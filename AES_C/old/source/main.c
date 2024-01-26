#include "./include/aes_encryptor.h"

//Expand key
//Substitute bytes
//shifftRows
//mixColumns        X
//addroundkey

#include <malloc.h>

int main(int argc, char** argv){

    unsigned char message[] = "This is a message we will encrypt with AES!";
    unsigned char key[16] = {
        65, 66, 67, 68,
        69, 70, 71, 72, 
        73, 74, 75, 76,
        77, 78, 79, 80
    };

    int orglen = strlen((const char*)message);
    int paddedlen = orglen;

    if(paddedlen % 16 != 0){
        paddedlen = (paddedlen / 16 + 1) * 16;
    }

    unsigned char* padded_message = malloc(paddedlen * sizeof(unsigned char));
    for (int i = 0; i < paddedlen; i++)
    {
        if (i >= orglen) 
        {
            padded_message[i] = 0;
        }else{
            padded_message[i] = message[i];
        }
    }


    for (int i = 0; i < paddedlen; i+=16)
    {
        encrypt(padded_message+i, key);
    }
    

    
    for (int i = 0; i < 16; i++)
    {
        printf("%#2x; ", padded_message[i]);
    }
    printf("\n%s", padded_message);
    

    return 0;
}