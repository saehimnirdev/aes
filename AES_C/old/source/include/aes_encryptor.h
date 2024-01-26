#ifndef AES_ENCRYPTOR
#define AES_ENCRYPTOR

#include <stdio.h>
#include <string.h>

#include "lookup_tables.h"

#define ROUNDS 10

void encrypt(unsigned char* message, unsigned char* key);
void decrypt();

static void expandKey(unsigned char* inputKey, unsigned char* roundKeys);
static void substituteBytes(unsigned char* state);
static void shiftRows(unsigned char* state);
static void mixColumns(unsigned char* state);
static void addRoundKey(unsigned char* state, unsigned char* roundKey);

static void keyCore(unsigned char* key, unsigned char round);
#endif