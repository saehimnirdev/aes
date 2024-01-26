#include "../include/fileio.h"

char* readFile(char* filepath){

    //Opening specified file to encrypt
    FILE* fp = fopen(filepath, "rb");
 
    //Measuring filesize
    struct stat st;
    stat(filepath, &st);
    unsigned int fsize = st.st_size;

    //Allocating memory for the content of the file
    char* content = malloc(fsize) + 1;
    //reading the file
    fread(content, sizeof(char) * fsize, 1, fp);
    //Ending the char array with the null terminator for safety
    content[fsize] = '\0';
    //Closing the file
    fclose(fp);

    return content;
}

FILE* writeFile(char* filepath, char* content){

    FILE* fp = fopen(filepath, "wb");
    fwrite(content, strlen(content), 1, fp);
    fclose(fp);
    return fp;
}