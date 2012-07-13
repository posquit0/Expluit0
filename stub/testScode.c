/* loader.c -- load shellcode and run */

#if defined _WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>


int main(int argc, char **argv) {
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
	fprintf(stderr,"[*] Loading shellcode from \"%s\"...\n", argv[1]);
    	fp = fopen(argv[1], "r+b");
        if( fp == NULL ) {
		fprintf(stderr,"[*] Error: unable to open file \"%s\"\n", argv[1]);
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
	
	/* Run!! */
	funct = (int (*)()) filebuf;
	(int)(*funct)();
	
	
	return (0);
}

