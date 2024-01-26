#include "../include/aes128.h"

//Userfunctions
unsigned char* aes_encrypt(struct aes* aes){

    //Getting the Length of the message
    int originalLength = strlen((const char*)aes->message);
    int lengthOfPaddedMessage = originalLength;

    //Checking wether padding will is needed or not
    if (lengthOfPaddedMessage % 16 != 0)
    {
        //Rounding the length to the next greater multiple of 16
        lengthOfPaddedMessage = (lengthOfPaddedMessage / 16 + 1) * 16;
    }
    //Allocating memory for the padded String
    unsigned char* paddedMessage = (unsigned char*)malloc(sizeof(unsigned char) * lengthOfPaddedMessage);
    //Adding 0 to the Right of the String 
    for (int i = 0; i < lengthOfPaddedMessage; i++)
    {
        if (i >= originalLength)
        {
            paddedMessage[i] = 0;
        }else
        {
            paddedMessage[i] = aes->message[i];
        }
    }
    //Setting the length in the struct for later decryption
    aes->paddLen = lengthOfPaddedMessage;
    
    //Encrypting each 16 byte block 
    for (int i = 0; i < lengthOfPaddedMessage; i+=16)
    {
        aes_encrypt_block(paddedMessage+i, aes->key);
    }

    //Outputting the ciphered message
    printf("Encrypted Bytes:\n");
    for (int i = 0; i < lengthOfPaddedMessage; i++)
    {
        printf("%#x ", paddedMessage[i]);
    }
    //Setting the Cipher of the encrytor to the encrypted message for later decryption
    aes->cipher = paddedMessage;

    //returning the encrypted message
    return paddedMessage;
}
unsigned char* aes_decrypt(struct aes* aes){

    //Creating a buffer for the decrypted message
    unsigned char* paddedMessage = (unsigned char*)malloc(sizeof(unsigned char) * aes->paddLen);
    //Checking if cipher is foratted correctly
    if (aes->paddLen % 16 != 0)
    {
        //In case not, the function returns
        printf("FAILED!");
        return 0;
    }else{
        //In case yes, copying the message block
        for (int i = 0; i < aes->paddLen; i++)
        {
            paddedMessage[i] = aes->cipher[i];
        }   
    }

    //Decrypting 
    for (int i = 0; i < aes->paddLen; i+=16)
    {
        aes_decrypt_block(paddedMessage+i, aes->key);
    }

    //Printing the decrypted message
    printf("\nDecrypted String:\n%s\n", paddedMessage);

    //returning message
    return paddedMessage;
}

FILE* aes_encrypt_file(struct aes* aes, char* filepath){

    aes->message = readFile(filepath);
    aes->paddLen = strlen(aes->message);
    FILE* fp = writeFile(filepath, aes_encrypt(aes));
    return fp;
}
FILE* aes_decrypt_file(struct aes* aes, char* in_filepath, char* out_filepath){

    aes->cipher = readFile(in_filepath);
    aes->paddLen = strlen(aes->cipher);
    FILE* fp = writeFile(out_filepath, aes_decrypt(aes));
    return fp;
}

//Core Encryptipn and Decryption
static void aes_encrypt_block(unsigned char* message, unsigned char* key){

    //Deklaring and initializing an array of 16 characters
    unsigned char state[16];

    //Copying the message to the state array
    for (int i = 0; i < 16; i++)
    {
        state[i] = message[i];
    }
    
    //Defining the number of Rounds - 1, in AES 128 10, thus here 9
    int numberOfRounds = 9;
    //Deklaring arn array for the roundkeys
    unsigned char expandedKey[176];
    //Expand the userkey to get the roundkeys
    keyExpansion(key, expandedKey);
    //Adding the Roundkey by xor-ing the state with the key
    addRoundKey(state, key);

    //main loop
    for (int i = 0; i < numberOfRounds; i++)
    {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey + (16 * (i + 1)));
    }
    //Last round of the encryption
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey + 160);
    
    //copying the state buffer to the original message thus overiding it
    for (int i = 0; i < 16; i++)
    {
        message[i] = state[i];
    }
}
static void aes_decrypt_block(unsigned char* cipher, unsigned char* key){

    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = cipher[i];
    }

    int numberOfRounds = 9;
    unsigned char expandedKey[176];
    keyExpansion(key, expandedKey);

    addRoundKey(state, expandedKey + 160);
    invShiftRows(state);
    invSubBytes(state);

    for (int i = 0; i < numberOfRounds; i++) {
        addRoundKey(state, expandedKey + (16 * (numberOfRounds - i)));
        invMixColumns(state);
        invShiftRows(state);
        invSubBytes(state);
    }

    addRoundKey(state, key);

    for (int i = 0; i < 16; i++) {
        cipher[i] = state[i];
    }
}

//Nessecairy utilityfunctios
struct aes* createAES(unsigned char* message, unsigned char* key){

    struct aes* aes = malloc(sizeof(struct aes));
    aes->message = message;
    aes->key = key;

    return aes;
}
void destroyAES(struct aes* aes){

    free(aes);
}

//Subfunctions for the key
static void keyExpansion(unsigned char* inputKey, unsigned char* expandedKeys){

    //copying the key to the first 16 bytes of the expanded keys
    for (int i = 0; i < 16; i++)
    {
        expandedKeys[i] = inputKey[i];
    }
    //Keeping track of the generated bytes
    int bytesGenerated = 16;
    //Keeping track of the current rconIteration, maximum of 10
    int rconIteration = 1;
    //Temporary array of the previous for bytes 
    unsigned char tmp[4];

    //While loop to generate full expanded key of size 176 bytes
    while (bytesGenerated < 176)
    {
        //Initialization of every element of tmp array with the previous byte, so that tmp contains the previous 4 bytes
        for (int i = 0; i < 4; i++)
        {
            tmp[i] = expandedKeys[i + bytesGenerated - 4];
        }
        //Main keyExpansion steps
        if (bytesGenerated % 16 == 0)
        {
            keyExpansionCore(tmp, rconIteration);
            rconIteration++;
        }
        //xor-ing the expanded key with the tmp array
        for (int a = 0; a < 4; a++)
        {
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ tmp[a];
            bytesGenerated++;
        }
    }  
}
static void keyExpansionCore(unsigned char* in, unsigned char i){

    //Rotating a word, or 4 bytes one to the left and append the leftover
    unsigned int* q = (unsigned int*)in;
    *q = (*q >> 8) | ((*q & 0xff) << 24);

    //substituting the bytest with their correspondant value in the s box
    in[0] = s_box[in[0]];
    in[1] = s_box[in[1]];
    in[2] = s_box[in[2]];
    in[3] = s_box[in[3]];

    //xor-ing the first byte of the word with the correspondant entry in the r_con table(rounding constants) 
    in[0] ^= r_con[i];
}
static void addRoundKey(unsigned char* state, unsigned char* roundKey){

    //xor-ing each state of the byte with the corresponding byte in the roundkey
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}

//Substeps of the Encryption
static void subBytes(unsigned char* state){

    //Substitute eacht byte of the state with the entry in the sbox corresponding to the value of the state byte 
    for (int i = 0; i < 16; i++)
    {
        state[i] = s_box[state[i]];
    }   
}
static void shiftRows(unsigned char* state){

    //Manually shifting the rows like this:
    //
    //  0, 4, 8, 12,                \       0, 4, 8, 12,
    //  1, 5, 9, 13,    -------------\      5, 9, 13, 1,
    //  2, 6, 10,14,    -------------/      10,14, 2, 6,
    //  3, 7, 11,15                 /       15, 3, 7,11

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
    
    //copying the buffer of tmp to state
    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}
static void mixColumns(unsigned char* state){

    //Declaring a temporary array of 16 bytes
    unsigned char tmp[16];

    //Matrixmultiplication unsing xor due to the gallois field and the precalculated mat_mul_n tables
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

    //Copying the buffer to the original state array
    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    } 
}

//Substeps of the Decryption
static void invSubBytes(unsigned char* state){

    //Substituting the bytes of the state with their corresponding entry in the inverse s_box table to revert the previous substitution
    for (int i = 0; i < 16; i++)
    {
        state[i] = i_s_box[state[i]];
    }   
}
static void invShiftRows(unsigned char* state){

    //Once again manually shifting the rows of the state matrix but in reverse order to revert to the previous state 
    unsigned char tmp[16];
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];
    
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];
    
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];
    
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];
    
    //Copying the buffer to the original state array
    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
    
}
static void invMixColumns(unsigned char* state){

    //Declaring an array buffer to store the transformed state
    unsigned char tmp[16];

    //Matrixmultiplication using the matrix multiplication tables mat_mul_n to transform the marix of the oiginal state
    tmp[0] = (unsigned char)(mat_mul_14[state[0]] ^ mat_mul_11[state[1]] ^ mat_mul_13[state[2]] ^ mat_mul_9[state[3]]);
    tmp[1] = (unsigned char)(mat_mul_9[state[0]] ^  mat_mul_14[state[1]] ^ mat_mul_11[state[2]] ^ mat_mul_13[state[3]]);
    tmp[2] = (unsigned char)(mat_mul_13[state[0]] ^ mat_mul_9[state[1]] ^  mat_mul_14[state[2]] ^ mat_mul_11[state[3]]);
    tmp[3] = (unsigned char)(mat_mul_11[state[0]] ^ mat_mul_13[state[1]] ^ mat_mul_9[state[2]] ^ mat_mul_14[state[3]]);

    tmp[4] = (unsigned char)(mat_mul_14[state[4]] ^ mat_mul_11[state[5]] ^ mat_mul_13[state[6]] ^ mat_mul_9[state[7]]);
    tmp[5] = (unsigned char)(mat_mul_9[state[4]] ^  mat_mul_14[state[5]] ^ mat_mul_11[state[6]] ^ mat_mul_13[state[7]]);
    tmp[6] = (unsigned char)(mat_mul_13[state[4]] ^ mat_mul_9[state[5]] ^  mat_mul_14[state[6]] ^ mat_mul_11[state[7]]);
    tmp[7] = (unsigned char)(mat_mul_11[state[4]] ^ mat_mul_13[state[5]] ^ mat_mul_9[state[6]] ^  mat_mul_14[state[7]]);
    
    tmp[8] = (unsigned char)( mat_mul_14[state[8]] ^ mat_mul_11[state[9]] ^ mat_mul_13[state[10]] ^ mat_mul_9[state[11]]);
    tmp[9] = (unsigned char)( mat_mul_9[state[8]] ^  mat_mul_14[state[9]] ^ mat_mul_11[state[10]] ^ mat_mul_13[state[11]]);
    tmp[10] = (unsigned char)(mat_mul_13[state[8]] ^ mat_mul_9[state[9]] ^  mat_mul_14[state[10]] ^ mat_mul_11[state[11]]);
    tmp[11] = (unsigned char)(mat_mul_11[state[8]] ^ mat_mul_13[state[9]] ^ mat_mul_9[state[10]] ^  mat_mul_14[state[11]]);

    tmp[12] = (unsigned char)(mat_mul_14[state[12]] ^ mat_mul_11[state[13]] ^ mat_mul_13[state[14]] ^ mat_mul_9[state[15]]);
    tmp[13] = (unsigned char)(mat_mul_9[state[12]] ^  mat_mul_14[state[13]] ^ mat_mul_11[state[14]] ^ mat_mul_13[state[15]]);
    tmp[14] = (unsigned char)(mat_mul_13[state[12]] ^ mat_mul_9[state[13]] ^  mat_mul_14[state[14]] ^ mat_mul_11[state[15]]);
    tmp[15] = (unsigned char)(mat_mul_11[state[12]] ^ mat_mul_13[state[13]] ^ mat_mul_9[state[14]] ^  mat_mul_14[state[15]]);

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    } 
}