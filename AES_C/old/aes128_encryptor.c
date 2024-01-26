#include "../include/aes128_encryptor.h"
#include <stdio.h>
#include <string.h>

/*
struct aes128_encryptor* createAESEncryptor(byte* data, byte* userkey){

    struct aes128_encryptor* encryptor = malloc(sizeof(struct aes128_encryptor));
    encryptor->data = data;
    encryptor->userkey = userkey;
    encryptor->roundkey = userkey;

    return encryptor;
}

byte* encrypt(struct aes128_encryptor* encryptor){

    byte i = 0;

    addRoundKey(encryptor);
    for(i = 1; i < 10; i++){
        substituteBytes(encryptor);
        shiftRows(encryptor);
        mixColumns(encryptor);
        expandKey(encryptor, i);
        addRoundKey(encryptor);
        printf("Round %i:\t", i);
        for(int j = 0; j < BLOCK_SIZE; j++){
            printf("%i; ", encryptor->data[j]);
        }
        printf("\n");
    }
    substituteBytes(encryptor);
    shiftRows(encryptor);
    expandKey(encryptor, i);
    addRoundKey(encryptor);

    return "Replace Later";
}

byte expandKey(struct aes128_encryptor* encryptor, byte i){
    
    byte w0[4];
    byte w1[4];
    byte w2[4];
    byte w3[4];

    for (int i = 0; i < 4; i++)
    {
        w0[i] = encryptor->userkey[i];
        w1[i] = encryptor->userkey[i+4];
        w2[i] = encryptor->userkey[i+8];
        w3[i] = encryptor->userkey[i+12];
    }

    printf("%i, %i, %i, %i\n", w0[0], w0[1], w0[2], w0[3]);
    printf("%i, %i, %i, %i\n", w1[0], w1[1], w1[2], w1[3]);
    printf("%i, %i, %i, %i\n", w2[0], w2[1], w2[2], w2[3]);
    printf("%i, %i, %i, %i\n", w3[0], w3[1], w3[2], w3[3]);

    byte tmp = w3[0];
    w3[0] = w3[1];
    w3[1] = w3[2];
    w3[2] = w3[3];
    w3[3] = tmp;

    printf("\n");    
    printf("%i, %i, %i, %i\n", w0[0], w0[1], w0[2], w0[3]);
    printf("%i, %i, %i, %i\n", w1[0], w1[1], w1[2], w1[3]);
    printf("%i, %i, %i, %i\n", w2[0], w2[1], w2[2], w2[3]);
    printf("%i, %i, %i, %i\n", w3[0], w3[1], w3[2], w3[3]);

    for (int i = 0; i < 4; i++)
    {
        w3[i] = s_box[w3[i]];
    }
    printf("\n");
    printf("%i, %i, %i, %i\n", w0[0], w0[1], w0[2], w0[3]);
    printf("%i, %i, %i, %i\n", w1[0], w1[1], w1[2], w1[3]);
    printf("%i, %i, %i, %i\n", w2[0], w2[1], w2[2], w2[3]);
    printf("%i, %i, %i, %i\n", w3[0], w3[1], w3[2], w3[3]);
    
    w3[0] ^= r_con[i];
    printf("RoundKey\n");
    printf("%i, %i, %i, %i\n", w0[0], w0[1], w0[2], w0[3]);
    printf("%i, %i, %i, %i\n", w1[0], w1[1], w1[2], w1[3]);
    printf("%i, %i, %i, %i\n", w2[0], w2[1], w2[2], w2[3]);
    printf("%i, %i, %i, %i\n", w3[0], w3[1], w3[2], w3[3]);
    
    encryptor->roundkey[0] = w0[0];
    encryptor->roundkey[1] = w0[1];
    encryptor->roundkey[2] = w0[2];
    encryptor->roundkey[3] = w0[3];
    encryptor->roundkey[4] = w1[0];
    encryptor->roundkey[5] = w1[1];
    encryptor->roundkey[6] = w1[2];
    encryptor->roundkey[7] = w1[3];
    encryptor->roundkey[8] = w2[0];
    encryptor->roundkey[9] = w2[1];
    encryptor->roundkey[10] = w2[2];
    encryptor->roundkey[11] = w2[3];
    encryptor->roundkey[12] = w3[0];
    encryptor->roundkey[13] = w3[1];
    encryptor->roundkey[14] = w3[2];
    encryptor->roundkey[15] = w3[3];
}  

byte addRoundKey(struct aes128_encryptor* encryptor){
    
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        encryptor->data[i] ^= encryptor->roundkey[i];
    }
    
}

byte substituteBytes(struct aes128_encryptor* encryptor){

    for(int i = 0; i < BLOCK_SIZE; i++){
        encryptor->data[i] = s_box[encryptor->data[i]];
    }
}

byte shiftRows(struct aes128_encryptor* encryptor){

    //0, 1, 2, 3,               \       0, 1, 2, 3,
    //4, 5, 6, 7,       -------  \      5, 6, 7, 4,
    //8, 9,10, 11,      -------  /      10,11,8, 9,
    //12,13,14,15               /       15,12,13,14
    byte tmp1 = encryptor->data[4];
    
    encryptor->data[4] = encryptor->data[5];
    encryptor->data[5] = encryptor->data[6];
    encryptor->data[6] = encryptor->data[7];
    encryptor->data[7] = tmp1;

    tmp1 = encryptor->data[8];
    byte tmp2 = encryptor->data[9];
    
    encryptor->data[8] = encryptor->data[10];
    encryptor->data[9] = encryptor->data[11];
    encryptor->data[10] = tmp1;
    encryptor->data[11] = tmp2;

    tmp1 = encryptor->data[15];
    encryptor->data[15] = encryptor->data[14];
    encryptor->data[14] = encryptor->data[13];
    encryptor->data[13] = encryptor->data[12];
    encryptor->data[12] = tmp1;
}

byte mixColumns(struct aes128_encryptor* encryptor){

    //0, 1, 2, 3,               \       0, 1, 2, 3,
    //4, 5, 6, 7,       -------  \      5, 6, 7, 4,
    //8, 9,10, 11,      -------  /      10,11,8, 9,
    //12,13,14,15               /       15,12,13,14

    byte byte1, byte2, byte3, byte4;

    for (int i = 0; i < 4; i++){
        byte1 = encryptor->data[0+i];
        byte2 = encryptor->data[4+i];
        byte3 = encryptor->data[8+i];
        byte4 = encryptor->data[12+i]; 

        encryptor->data[0+i] = (xtimes(byte1)) ^ ((byte2*2) ^ byte2) ^ (byte3) ^ (byte4);
        encryptor->data[4+i] = (byte1) ^ (xtimes(byte2)) ^ ((byte3*2) ^ byte3) ^ (byte4);
        encryptor->data[8+i] = (byte1) ^ (byte2) ^ (xtimes(byte3)) ^ ((byte4*2) ^ byte4);
        encryptor->data[12+i] = ((byte1*2) ^ byte1) ^ (byte2) ^ (byte3) ^ (xtimes(byte4));
    }

}

byte xtimes(byte x){

    //equivalent zu:             hier:
    //if (x < 128){             |(x & 0x80)//folgt aus binär 1000 0000 = 128
    //  return 2*x;             |(x << 1)//ebenfallst aus binär bsp 1 << 1 = 0001 << 1 = 0010 = 2
    //}else {                   |
    //  return (2*x) ^ 0x1b       |(x<<1) ^ 0x1b//theoretisch 0x11b, aber nur 0x1b da mit bytes gearbeitet wird
    //}                         |
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}

void rotateWord(byte* word){

    byte tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void substituteWord(byte* word){

    word[0] = s_box[word[0]];
    word[1] = s_box[word[1]];
    word[2] = s_box[word[2]];
}

byte* addPadding(byte* str){

    int len = strlen(str);
    int len_mod = 16 - (len % 16);
    byte* buff = malloc(sizeof(char)*(len+len_mod+1));
    if (len_mod == 0){
        strcpy(buff, str);
        return buff;
    }else{
        strcpy(buff, str);
        for (int i = len; i < len + len_mod; i++){
            buff[i] = '0';
        }
        buff[len+len_mod] = '\0';
        return buff;
    }
}

struct * format(byte* data){

    int len = strlen(data);
    byte* buff;
    struct message* message = malloc(sizeof(struct message));
    if (len % 16 != 0){
        buff = addPadding(data);
        printf("insufficient padding...\npadding\n");
        message = format(buff);
    }else{
        message->size = len/16;
        message->data = malloc(16*sizeof(char)*message->size);
        for (int  i = 0; i < message->size; i++)
        {
            buff = spliteBytes(data, 0+(16*i), 16*(i+1));
            message->data[i] = buff;   
        }
    }

    return message;
}

byte* spliteBytes(byte* str, int from, int to){


    byte* buff = malloc(sizeof(byte) * (to - from));
    for (int i = 0; i < to-from; i++)
    {
        buff[i] = str[from+i];
    }
    buff[to-from] = '\0';
    return buff;
}*/