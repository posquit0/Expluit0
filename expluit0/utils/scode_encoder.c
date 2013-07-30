
/*
 *
 * encoder.c - Encode NULLs and other characters out of shellcode
 * Copyright (c) Jarkko Turkulainen 2004. All rights reserved.
 *
 * Compile: cl encoder.c (MS Visual C)
 *          cc -o encoder encoder.c (Unix)
 *
 * This program tries to eliminate NULLs and other user-defined
 * characters out of shellcode. It uses a simple XOR and includes
 * a built-in decoder routine for x86.
 *
 * This program is public domain, do whatever pleases you with it.
 * If you like it, let me know!
 *
 * Usage: encoder <shellcode> <bytes> [-f|-j|-n]
 * 
 * - "shellcode" is the binary shellcode file
 * - "bytes" are comma-separated list of bytes that are encoded
 * - Use "-f" for FNSTENV XOR byte decoder (default)
 * - Use "-j" for traditional jump/call decoder
 * - Use "-n" if you don't need the built-in decoder
 * - If no decoder defined, "-f" is used
 * - Encoded shellcode is printed in _standard_output_ (NOTE!!!)
 *
 * Example: encoder code.s 0x00,0x0a,0x0d > out.s
 *
 * How it works: It tries to find a number that won't produce any of the
 * user-defined bytes when XOR'ed with any of the bytes in shellcode. If
 * it finds a one, it XORs the shellcode with that number. And in the end,
 * it adjusts the built-in decoder to produce and run the original 
 * shellcode (if -n was not defined in command line). Very simple in theory,
 * and it seems to even work sometimes.
 *
 * How to customize:
 *
 * - Change the decoder register (eax, ebx or edx)
 */
#define REGISTER "eax"


/*
 * Credits:
 * H.D. Moore, http://metasploit.com (FNSTENV XOR byte decoder)
 * Steve Fewer, http://www.harmonysecurity.com (jump/call decoder)
 *
 */


#if defined _WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Register codes */
#define REG_EAX		0
#define REG_EBX		1
#define REG_ECX		2
#define REG_EDX		3

/* Decoders */
#define	DECODER_FNSTENV	0
#define DECODER_JUMP	1
#define DECODER_NONE	2

/* Actual decoders, DO NOT MODIFY! */
unsigned char decoder_fnstenv_header[] = {
	0xD9, 0xE1, 0xD9, 0x34, 0x24, 0x5B, 0x5B, 0x5B, 
	0x5B, 0x80, 0xEB, 0xE7, 0x31, 0xC9, 0x66, 0x81, 
	0xE9, 0xA1, 0xFE, 0x80, 0x33, 0x99, 0x43, 0xE2, 
	0xFA
};
unsigned char decoder_jump_header[] = {
	0xEB, 0x10, 0x5B, 0x31, 0xC9, 0x66, 0x81, 0xE9, 
	0xA1, 0xFE, 0x80, 0x33, 0x99, 0x43, 0xE2, 0xFA, 
	0xEB, 0x05, 0xE8, 0xEB, 0xFF, 0xFF, 0xFF
};


#define VERSION	"0.6"

int main(int argc, char **argv) {
	char		*ptr, *filebuf, *shellbuf;
	struct stat	sstat;
	FILE 		*fp;
	int		i, j, k, c;
	int		reg, try, found;
	int		decoder, total, len, size;
	unsigned char	encode_byte, *encode_bytes;
	
	/* Print banner */
	fprintf(stderr,"\nEncoder v%s - Encode NULLs and other characters out of shellcode\n"
		"Copyright (c) Jarkko Turkulainen 2004. All rights reserved.\n"
		"Read the file encoder.c for documentation.\n\n", VERSION);

	/* Check command line parameters */
	if (argc < 3) {
		fprintf(stderr,"Usage: %s <shellcode> <bytes> [-f|-j|-n] \n"
			"\t-f use FNSTENV XOR byte decoder\n"
			"\t-j use traditional jump/call decoder\n"
			"\t-n do not include decoder in output\n", argv[0]);
		fprintf(stderr,"\nExample: encoder code.s 0x00,0x0a,0x0d > out.s\n\n");
		exit(0);
        }

	/* Open shellcode file */
	fprintf(stderr,"Reading shellcode from \"%s\"\n", argv[1]);
    	fp = fopen(argv[1], "r+b");
        if( fp == NULL ) {
		fprintf(stderr,"\nERROR: unable to open file \"%s\"\n", argv[1]);
		exit(0);
        }

	if ((argc >= 4) && !strncmp(argv[3], "-n", 2))
		decoder = DECODER_NONE;
	else if ((argc >= 4) && !strncmp(argv[3], "-j", 2)) {
		decoder = DECODER_JUMP;
		fprintf(stderr,"Using jump/call decoder\n"
			"Using register %s for decoder\n", REGISTER);
	} else {
		decoder = DECODER_FNSTENV;
		fprintf(stderr,"Using FNSTENV XOR decoder\n"
			"Using register %s for decoder\n", REGISTER);
	}
	/* Check out register */
	if (!strncmp(REGISTER, "eax", 3))
		reg = REG_EAX;
	else if (!strncmp(REGISTER, "ebx", 3))
		reg = REG_EBX;
	else if (!strncmp(REGISTER, "edx", 3))
		reg = REG_EDX;
	else
		reg = REG_EDX;

	/* Scan for encode bytes, 1st round */
	for (i = 1, ptr= argv[2]; *ptr != '\0'; ptr++) {
		if (*ptr == ',') i++;
	}

	/* Space for encode bytes: */
	size = i;
	if (!(encode_bytes = (unsigned char *)malloc(size * sizeof(unsigned char))))
		exit (1);
	

	/* Scan for encode bytes, 2nd round */
	encode_bytes[0] =  strtoul(argv[2], NULL, 0);
	for (i = 1, ptr = argv[2]; *ptr != '\0'; ptr++) {
		if ((*ptr == ',') && (*(ptr+1) != '\0')) {
			encode_bytes[i] =  strtoul(ptr+1, NULL, 0);
			i++;
		}
	}
	fprintf(stderr,"Removing bytes");
	for (i = 0; i < size; i++)
		fprintf(stderr," 0x%.2X", encode_bytes[i]);
	fprintf(stderr,"\n");

	/* Check the decoders for encode_bytes */
	if (decoder == DECODER_FNSTENV) {
		ptr = decoder_fnstenv_header;
		c = sizeof(decoder_fnstenv_header);
	} else if (decoder == DECODER_JUMP) {
		ptr = decoder_jump_header;
		c = sizeof(decoder_jump_header);
	}
	for (i = 0; i < size; i++) {
		if (decoder == DECODER_NONE) break;
		for (j = 0; j < c; j++) {
			try = ptr[j]&0xff;
			if (encode_bytes[i] == try) {
				fprintf(stderr,"\nWARNING: 0x%.2X found in "
					"decoder routine\n\n", encode_bytes[i]);
				break;
			}
		}
	}

	/* Determine file len */
	c = stat(argv[1], &sstat);
	if (c == -1) {
		exit (1);
	}
	len = sstat.st_size;
	if ((len > 0xffff) && (decoder != DECODER_NONE)) {
		fprintf(stderr,"\nWARNING: file size >0xFFFF, disabling decoder\n\n");
		decoder = DECODER_NONE;
	}

	/* Allocate space for file */
	if (!(filebuf = (char *)malloc(len)))
		exit (1);

	/* Read file in allocated space */
	c = fread(filebuf, 1, len, fp);
	fclose(fp);
	if (c != len) {
		exit (1);
	}
	
	/* Scan the shellcode for suitable encode byte */
	for (i = 1; i < 255; i++) {

		/* Mark the candidate as found */
		found = 1;

		/* Try out every byte in encode_bytes array */
		for (j = 0; j < size; j++) {

			/* XOR candidate with encode_bytes */
			try = i^encode_bytes[j];
			
			/* Now try every byte in shellcode */
			for (k = 0; k < len; k++) {

				c = 0xff&filebuf[k];
	
				/* If match, mark the candidate "not found" */
				if (c == try) {
					found = 0;
					break;
				}
			}
		}
		/* Break out if byte found */
		if (found == 1) break;
	}
	if (found == 1) {
		fprintf(stderr,"Using 0x%.2X for XOR\n", i);
		encode_byte = i;
	} else {
		fprintf(stderr,"\nERROR: cannot found encode byte value\n");
		exit (0);
	}

	/* No decoder, simple print: */
	if (decoder == DECODER_NONE) {
		for (c = 0; c < len; c++) {
			fputc(filebuf[c]^encode_byte, stdout);
		}
		fprintf(stderr,"Ready\n");
		exit (0);
	}

	/* Allocate space for final shellcode */
	if (decoder == DECODER_JUMP) {
		total = len + sizeof(decoder_jump_header);
	} else {
		total = len + sizeof(decoder_fnstenv_header);
	}
	if (!(shellbuf = (char *)malloc(total)))
		exit (1);

	/* Create the new shellcode */

	/* jump/call decoder */

	if (decoder == DECODER_JUMP) {
		/* Copy 1st header */
		memcpy(&shellbuf[0], decoder_jump_header, 
			sizeof(decoder_jump_header));

		/* Copy the actual shellcode */
		for (i = 0; i < len; i++)
			filebuf[i] = filebuf[i]^encode_byte;
		memcpy(&shellbuf[sizeof(decoder_jump_header)], 
			filebuf, len);

		/* High len byte: */
		shellbuf[9] = ((0x10000-len)>>8)&0xff;

		/* Low len byte: */
		shellbuf[8] = (0x10000-len)&0xff;
		/* Adjust, if needed.. */
		if (shellbuf[8] == 0)
			shellbuf[8]++;

		/* XOR byte */
		shellbuf[12] = encode_byte;

		/* Decoder register */
		switch (reg) {
			case REG_EAX:
				shellbuf[2] = 0x58;
				shellbuf[11] = 0x30;
				shellbuf[13] = 0x40;
				break;
			case REG_EDX:
				shellbuf[2] = 0x5a;
				shellbuf[11] = 0x32;
				shellbuf[13] = 0x42;
				break;
			case REG_EBX:
				shellbuf[2] = 0x5b;
				shellbuf[11] = 0x33;
				shellbuf[13] = 0x43;
				break;
		}
		
	/* FNSTENV XOR byte decoder */

	} else {

		/* Copy header */
		memcpy(&shellbuf[0], decoder_fnstenv_header, 
			sizeof(decoder_fnstenv_header));

		/* Copy the actual shellcode */
		for (i = 0; i < len; i++)
			filebuf[i] = filebuf[i]^encode_byte;
		memcpy(&shellbuf[sizeof(decoder_fnstenv_header)], 
			filebuf, len);

		/* High len byte: */
		shellbuf[18] = ((0x10000-len)>>8)&0xff;

		/* Low len byte: */
		shellbuf[17] = (0x10000-len)&0xff;
		/* Adjust, if needed.. */
		if (shellbuf[17] == 0)
			shellbuf[17]++;

		/* XOR byte */
		shellbuf[21] = encode_byte;

		/* Decoder register */
		switch (reg) {
			case REG_EAX:
				shellbuf[5] = 0x58;
				shellbuf[6] = 0x58;
				shellbuf[7] = 0x58;
				shellbuf[8] = 0x58;
				shellbuf[10] = 0xe8;
				shellbuf[20] = 0x30;
				shellbuf[22] = 0x40;
				break;
			case REG_EDX:
				shellbuf[5] = 0x5a;
				shellbuf[6] = 0x5a;
				shellbuf[7] = 0x5a;
				shellbuf[8] = 0x5a;
				shellbuf[10] = 0xea;
				shellbuf[20] = 0x32;
				shellbuf[22] = 0x42;
				break;
			case REG_EBX:
				shellbuf[5] = 0x5b;
				shellbuf[6] = 0x5b;
				shellbuf[7] = 0x5b;
				shellbuf[8] = 0x5b;
				shellbuf[10] = 0xeb;
				shellbuf[20] = 0x33;
				shellbuf[22] = 0x43;
				break;
		}

	}

	/* Print out the code */
	for (c = 0; c < total; c++) {
		fputc(shellbuf[c], stdout);
	}
	fprintf(stderr,"Ready\n");
	
	return (0);
}

