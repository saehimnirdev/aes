#ifndef FILE_IO_H
#define FILE_IO_H

#include <sys/stat.h>
#include <stdio.h>
#include <malloc.h>

char* readFile(char* filepath);
FILE* writeFile(char* filepath, char* content);

#endif