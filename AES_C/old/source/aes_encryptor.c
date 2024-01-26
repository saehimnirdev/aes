#include "./include/aes_encryptor.h"

void encrypt(unsigned char* message, unsigned char* key){

    unsigned char state[16];

    for(int i = 0; i < 16; i++){
        state[i] = message[i];
    } 

    unsigned char rounds = 9;
    unsigned char expandedKey[176];

    expandKey(key, expandedKey);
    addRoundKey(state, key);

    for(int i = 0; i < rounds; i++){
        substituteBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey + (16 * (i + 1)));
    }

    substituteBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey + 160);

    for(int i = 0; i < 16; i++){

        message[i] = state[i];
    }   
}

void decrypt(){

}

static void expandKey(unsigned char* inputKey, unsigned char* roundKeys){

    for(int i = 0; i < 16; i++){
        roundKeys[i] = inputKey[i];
    }

    int byteCount = 16;
    int rconIter = 1;
    unsigned char tmp[4];

    while(byteCount < 176){
        for(int i = 0; i < 4; i++){
            tmp[i] = roundKeys[i + byteCount - 4];
        }
        if(byteCount % 16 == 0){
            keyCore(tmp, rconIter);
            rconIter++;
        }
        for(unsigned char j = 0; j < 4; j++){
            roundKeys[byteCount] = roundKeys[byteCount - 16] ^ tmp[j];
            byteCount++;
        }
    }
}

static void keyCore(unsigned char* prevKey, unsigned char round){

    unsigned char tmp = prevKey[0];
    prevKey[0] = prevKey[1];
    prevKey[1] = prevKey[2];
    prevKey[2] = prevKey[3];
    prevKey[3] = tmp;

    for(int i = 0; i < 4; i++){
        prevKey[i] = s_box[prevKey[i]];
    }

    prevKey[0] ^= r_con[round];
}

static void substituteBytes(unsigned char* state){

    for(int i = 0; i < 16; i++){
        state[i] = s_box[state[i]];
    }
}

static void shiftRows(unsigned char* state){

    //0, 4, 8, 12,          \       0, 4, 8, 12,
    //1, 5, 9, 13,      -----\      5, 9, 13, 1,
    //2, 6, 10, 14,     -----/      10, 14, 2, 6, 
    //3, 7, 11, 15          /       15, 3, 7, 11

    unsigned char tmp[16];
    
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }  
}

static void mixColumns(unsigned char* state){

    unsigned char tmp[16];
    tmp[0] = (unsigned char)(mat_mul_2[state[0]] ^ mat_mul_3[state[1]] ^ state[2] ^ state[3]);
    tmp[1] = (unsigned char)(state[0] ^ mat_mul_2[state[1]] ^ mat_mul_3[state[2]] ^ state[3]);
    tmp[2] = (unsigned char)(state[0] ^ state[1] ^ mat_mul_2[state[2]] ^ mat_mul_3[state[3]]);
    tmp[3] = (unsigned char)(mat_mul_3[state[0]] ^ state[1] ^ state[2] ^ mat_mul_2[state[3]]);

    tmp[4] = (unsigned char)(mat_mul_2[state[4]] ^ mat_mul_3[state[5]] ^ state[6] ^ state[7]);
    tmp[5] = (unsigned char)(state[4] ^ mat_mul_2[state[5]] ^ mat_mul_3[state[6]] ^ state[7]);
    tmp[6] = (unsigned char)(state[4] ^ state[5] ^ mat_mul_2[state[6]] ^ mat_mul_3[state[7]]);
    tmp[7] = (unsigned char)(mat_mul_3[state[4]] ^ state[5] ^ state[6] ^ mat_mul_2[state[7]]);

    tmp[8] = (unsigned char)(mat_mul_2[state[8]] ^ mat_mul_3[state[9]] ^ state[10] ^ state[11]);
    tmp[9] = (unsigned char)(state[8] ^ mat_mul_2[state[9]] ^ mat_mul_3[state[10]] ^ state[11]);
    tmp[10] = (unsigned char)(state[8] ^ state[9] ^ mat_mul_2[state[10]] ^ mat_mul_3[state[11]]);
    tmp[11] = (unsigned char)(mat_mul_3[state[8]] ^ state[9] ^ state[10] ^ mat_mul_2[state[11]]);

    tmp[12] = (unsigned char)(mat_mul_2[state[12]] ^ mat_mul_3[state[13]] ^ state[14] ^ state[15]);
    tmp[13] = (unsigned char)(state[12] ^ mat_mul_2[state[13]] ^ mat_mul_3[state[14]] ^ state[15]);
    tmp[14] = (unsigned char)(state[12] ^ state[13] ^ mat_mul_2[state[14]] ^ mat_mul_3[state[15]]);
    tmp[15] = (unsigned char)(mat_mul_3[state[12]] ^ state[13] ^ state[14] ^ mat_mul_2[state[15]]);


}

static void addRoundKey(unsigned char* state, unsigned char* roundKey){

    for(int i = 0; i < 16; i++){
        state[i] ^= roundKey[i];
    }
}