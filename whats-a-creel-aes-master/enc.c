#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "print_hex.h"


#include <malloc.h>

int main(int argc, char** argv){

    unsigned char message[] = "This is a message we will encrypt with AES!";
    unsigned char key[16] = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
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
        padded_message = aes_encrypt(padded_message+i, key);
    }
    printf("%s\n", padded_message);

    for (int i = 0; i < paddedlen; i++)
    {
        //printf("%#2x; ", padded_message[i]);
        print_hex(padded_message);
    }
    
    return 0;
}