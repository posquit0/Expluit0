/* loader.c -- load shellcode and run */

#if defined _WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>


int main(int argc, char **argv) {
	char		*filebuf;
	struct stat	sstat;
	FILE 		*fp;
	int		    c, len;
	int 		(*funct)();
	
	/* Check command line parameters */
	if (argc < 2) {
        fprintf(stderr, "Usage: %s <shellcode filename>\n", argv[0]);
        exit(0);
    }

	/* Open shellcode file */
	fprintf(stdin, "[*] Loading shellcode from \"%s\"...\n", argv[1]);
    fp = fopen(argv[1], "r+b");
    if (fp == NULL) {
	    fprintf(stderr, "[*] Error: unable to open file \"%s\"\n", argv[1]);
	    exit(0);
    }

	/* Get file len */
	c = stat(argv[1], &sstat);
	if (c == -1) {
        exit(0);
	}
	len = sstat.st_size;

	/* Allocate space for file */
	if (!(filebuf = (char *)malloc(len))) {
        fprintf(stderr, "[*] Error: Failed to allocate memory.");
        exit(0);
    }

	/* Read file in allocated space */
	if (fread(filebuf, 1, len, fp) != len) {
        fprintf(stderr, "[*] Error: Failed to read shellcode from file.");
        exit(0);
	}
	
	fclose(fp);

	/* Execute the shellcode. */
	fprintf(stdin, "[*] Running shellcode...\n");
	funct = (int (*)()) filebuf;
	(int)(*funct)();
	fprintf(stdin, "[*] Shellcode returned execution successfully.\n");
	
	return 0;
}

