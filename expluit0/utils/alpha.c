#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

// Inverse Function of modify
// const char *modifiedBuf : pointer to string that you want to get
// const int modifiedLen : length of modifiedBuf string (doesn't incl NULL)
// char **restoredString : pointer of char * var which contains pointer to
//							generated string, this function allocate memory
//							for result string - you should free it
// int *restoredLen : pointer of int var which contains length of generated
//						string
void InverseModify(const char *modifiedBuf, const int modifiedLen, 
					char **restoredString, int *restoredLen)
{
	char binList[] = "FEHGBADCNMPOJILK";

	int frequencyTable[16];
	char *shellCodeBuffer;
	int i, j, k;

	int maxNum;

	// Build Shellcode String
	for (i = 0; i < 16; ++i)
		frequencyTable[i] = 0;
	shellCodeBuffer = (char *)malloc(modifiedLen * 2 + 1);
	for (i = 0; i < modifiedLen; ++i)
	{
		shellCodeBuffer[i * 2] = binList[(unsigned char)modifiedBuf[i] >> 4];
		++frequencyTable[(unsigned char)modifiedBuf[i] >> 4];
		shellCodeBuffer[i * 2 + 1] = binList[modifiedBuf[i] & 0x0f];
		++frequencyTable[modifiedBuf[i] & 0x0f];
	}
	shellCodeBuffer[modifiedLen * 2] = 0;

	// Padding for Build Desired Huffman Tree
	maxNum = frequencyTable[0];
	for (i = 1;i < 16; ++i)
		if (maxNum < frequencyTable[i])
			maxNum = frequencyTable[i];

	*restoredLen = maxNum * 16;
	*restoredString = (char *)malloc(*restoredLen + 1);
	for (i = 0; i < strlen(shellCodeBuffer); ++i)
		(*restoredString)[i] = shellCodeBuffer[i];
	free(shellCodeBuffer);
	for (j = 0; j < 16; ++j)
	{
		for (k = frequencyTable[j]; k < maxNum; ++k)
		{
			(*restoredString)[i] = binList[j];
			++i;
		}
	}
	(*restoredString)[*restoredLen] = 0;
}

int main( int *argc, char **argv)
{
	char		*filebuf;
	struct stat	sstat;
	FILE 		*fp;
	int		c, len;
	int 		(*funct)();
	
	/* Check command line parameters */
	if (argc < 2) {
		fprintf(stderr,"Usage: %s <shellcode filename>\n", argv[0]);
		exit(0);
        }

	/* Open shellcode file */
	fprintf(stderr,"[*] (alpha) Loading shellcode from \"%s\"...\n", argv[1]);
    	fp = fopen(argv[1], "r+b");
        if( fp == NULL ) {
		fprintf(stderr,"[*] (alpha) Error: unable to open file \"%s\"\n", argv[1]);
		exit(0);
        }
	/* Get file len */
	c = stat(argv[1], &sstat);
	if (c == -1) {
		exit (1);
	}
	len = sstat.st_size;

	/* Allocate space for file */
	if (!(filebuf = (char *)malloc(len)))
		exit (1);

	/* Read file in allocated space */
	c = fread(filebuf, 1, len, fp);
	fclose(fp);
	if (c != len) {
		exit (1);
	}
    

}
