#define AES_256

#include "../include/aes_encryptor.h"

byte* aes_encrypt(byte* data, byte* key){

    log_to_console(AES_COLOR_CLEAR, "Initializing encryptor...");
    struct aes_encryptor* encryptor = malloc(sizeof(struct aes_encryptor));
    log_to_console(AES_COLOR_CLEAR, "Formating input data...");
    encryptor->data = format(data);
    log_to_console(AES_COLOR_OK, "Data formated successfully!");
    log_to_console(AES_COLOR_CLEAR, "Formating input key...");
    encryptor->key = format(key);
    log_to_console(AES_COLOR_CLEAR, "Key formated successfully!");
    log_to_console(AES_COLOR_OK, "Encryptor initialized!");
    log_to_console(AES_COLOR_CLEAR, "Expanding the key...");
    
}

struct data_block* format(byte* data){

    int len = strlen(data);
    byte* buff;
    struct data_block* tmpdata = malloc(sizeof(struct data_block));

    if (len % BLOCK_SIZE != 0){
        buff = addPadding(data);
        log_to_console(AES_COLOR_WARNING, "Insufficient datasize, padding with \'0\'");
        tmpdata = format(buff);
        return tmpdata;
    }else{
        tmpdata->size = len/BLOCK_SIZE;
        tmpdata->data = malloc(BLOCK_SIZE*sizeof(char)*tmpdata->size);
        for (int  i = 0; i < tmpdata->size; i++)
        {
            buff = splitBytes(data, 0+(BLOCK_SIZE*i), BLOCK_SIZE*(i+1));
            tmpdata->data[i] = buff;   
        }        
        for (int i = 0; i < tmpdata->size; i++)
        {
            for(int j = 0; j < BLOCK_SIZE; j++){
                printf("%s%#2x; %s", AES_COLOR_DATA, (int)tmpdata->data[i][j], AES_COLOR_CLEAR); 
            }
            printf("\n");
        }

        return tmpdata;
    }
}

byte* splitBytes(byte* data, int from, int to){

    byte* buff = malloc(sizeof(byte) * (to - from));
    for (int i = 0; i < to-from; i++)
    {
        buff[i] = data[from+i];
    }
    buff[to-from] = '\0';
    return buff;
}

byte* addPadding(byte* data){

    int len = strlen(data);
    int len_mod = BLOCK_SIZE - (len % BLOCK_SIZE);
    byte* buff = malloc(sizeof(char)*(len+len_mod+1));
    if (len_mod == 0){
        strcpy(buff, data);
        return buff;
    }else{
        strcpy(buff, data);
        for (int i = len; i < len + len_mod; i++){
            buff[i] = '0';
        }
        buff[len+len_mod] = '\0';
        return buff;
    }
}

byte log_to_console(char* color, char* message){

    printf("%s%s%s\n", color, message, AES_COLOR_CLEAR);
    return 0;
}