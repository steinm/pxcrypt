#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <getopt.h>
#include <libintl.h>
#include <sys/types.h>
#include <regex.h>
#include <libgen.h>
#include "config.h"
#ifdef HAVE_GSF
#include <paradox-gsf.h>
#else
#include <paradox.h>
#endif

#ifdef MEMORY_DEBUGGING
#include <paradox-mp.h>
#endif

#ifdef ENABLE_NLS
#define _(String) gettext(String)
#else
#define _(String) String
#endif

/* errorhandler() {{{
 */
void errorhandler(pxdoc_t *p, int error, const char *str, void *data) {
	  fprintf(stderr, "PXLib: %s\n", str);
}
/* }}} */

/* usage() {{{
 * Output usage information
 */
void usage(char *progname) {
	int recode;

	printf(_("Version: %s %s http://sourceforge.net/projects/pxlib"), progname, VERSION);
	printf("\n");
	printf(_("Copyright: Copyright (C) 2005 Uwe Steinmann <uwe@steinmann.cx>"));
	printf("\n\n");
	printf(_("%s decrypts or encrypts a paradox file."), progname);
	printf("\n\n");
	printf(_("Usage: %s [OPTIONS] FILE"), progname);
	printf("\n\n");
	printf(_("General options:"));
	printf("\n");
	printf(_("  -h, --help          this usage information."));
	printf("\n");
	printf(_("  --version           show version information."));
	printf("\n");
	printf(_("  -v, --verbose       be more verbose."));
	printf("\n");
#ifdef HAVE_GSF
	if(PX_has_gsf_support()) {
		printf(_("  --use-gsf           use gsf library to read input file."));
		printf("\n");
	}
#endif
	printf("\n");
	printf(_("  -o, --output-file=FILE output data into file instead of stdout."));
	printf("\n\n");
	printf(_("Options to select mode:"));
	printf("\n");
	printf(_("  --mode=MODE         set operation mode (encrypt, decrypt)."));
	printf("\n");
	printf(_("  --encrypt           encrypt file."));
	printf("\n");
	printf(_("  --decrypt           decrypt file."));

	printf("\n\n");
	printf(_("Encryption/decryption options:"));
	printf("\n");
	printf(_("  --password=WORD     set password for encyption."));

	printf("\n");
	if(PX_is_bigendian())
		printf(_("libpx has been compiled for big endian architecture."));
	else
		printf(_("libpx has been compiled for little endian architecture."));
	printf("\n");
	printf(_("libpx has gsf support: %s"), PX_has_gsf_support() == 1 ? _("Yes") : _("No"));
	printf("\n");
	printf(_("libpx has version: %d.%d.%d"), PX_get_majorversion(), PX_get_minorversion(), PX_get_subminorversion());
	printf("\n\n");
}
/* }}} */

void put_long_le(char *cp, long lval)
{
	*cp++ = lval & 0xff;
	*cp++ = (lval >> 8) & 0xff;
	*cp++ = (lval >> 16) & 0xff;
	*cp++ = (lval >> 24) & 0xff;
}

/* main() {{{
 */
int main(int argc, char *argv[]) {
	pxhead_t *pxh;
	pxfield_t *pxf;
	pxdoc_t *pxdoc = NULL;
	pxdoc_t *pindexdoc = NULL;
	pxblob_t *pxblob = NULL;
	char *progname = NULL;
	char *data;
	int i, j, c; // general counters
	int decrypt = 0, encrypt = 0;
	int usegsf = 0;
	int verbose = 0;
	char *password = NULL;
	char *inputfile = NULL;
	char *outputfile = NULL;
	FILE *outfp = NULL;

#ifdef MEMORY_DEBUGGING
	PX_mp_init();
#endif

#ifdef ENABLE_NLS
	setlocale (LC_ALL, "");
	setlocale (LC_NUMERIC, "C");
	bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
	textdomain (GETTEXT_PACKAGE);
#endif

	/* Handle program options {{{
	 */
	progname = basename(strdup(argv[0]));
	while(1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{"verbose", 0, 0, 'v'},
			{"encrypt", 0, 0, 'e'},
			{"decrypt", 0, 0, 'd'},
			{"output-file", 1, 0, 'o'},
			{"password", 1, 0, 'p'},
			{"help", 0, 0, 'h'},
			{"mode", 1, 0, 4},
			{"use-gsf", 0, 0, 8},
			{"version", 0, 0, 11},
			{0, 0, 0, 0}
		};
		c = getopt_long (argc, argv, "icsxqvtf:b:r:p:o:n:h",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 4:
				if(!strcmp(optarg, "decrypt")) {
					decrypt = 1;
				} else if(!strcmp(optarg, "encrypt")) {
					encrypt = 1;
				}
				break;
			case 8:
				usegsf = 1;
				break;
			case 11:
				fprintf(stdout, "%s\n", VERSION);
				exit(0);
				break;
			case 'd':
				decrypt = 1;
				break;
			case 'e':
				encrypt = 1;
				break;
			case 'o':
				outputfile = strdup(optarg);
				break;
			case 'p':
				password = strdup(optarg);
				break;
			case 'h':
				usage(progname);
				exit(0);
				break;
			case 'v':
				verbose = 1;
				break;
		}
	}

	if (optind < argc) {
		inputfile = strdup(argv[optind]);
	}

	if(!inputfile) {
		fprintf(stderr, _("You must at least specify an input file."));
		fprintf(stderr, "\n");
		fprintf(stderr, "\n");
		usage(progname);
		exit(1);
	}
	/* }}} */

	/* Handle different program names {{{
	 */
	if(!strcmp(progname, "pxencrypt")) {
		decrypt = 0;
		encrypt = 1;
	} else if(!strcmp(progname, "pxdecrypt")) {
		decrypt = 1;
		encrypt = 0;
	}
	/* }}} */

	/* if none the output modes is selected then display info */
	if(decrypt == 0 && encrypt == 0)
		decrypt = 1;

	/* Create output file {{{
	 */
	if((outputfile == NULL) || !strcmp(outputfile, "-")) {
		outfp = stdout;
	} else {
		outfp = fopen(outputfile, "w");
		if(outfp == NULL) {
			fprintf(stderr, _("Could not open output file."));
			fprintf(stderr, "\n");
			exit(1);
		}
	}
	/* }}} */

	/* Open input file {{{
	 */
#ifdef MEMORY_DEBUGGING
	if(NULL == (pxdoc = PX_new2(errorhandler, PX_mp_malloc, PX_mp_realloc, PX_mp_free))) {
#else
	if(NULL == (pxdoc = PX_new2(errorhandler, NULL, NULL, NULL))) {
#endif
		fprintf(stderr, _("Could not create new paradox instance."));
		fprintf(stderr, "\n");
		exit(1);
	}

#ifdef HAVE_GSF
	if(PX_has_gsf_support() && usegsf) {
		GsfInput *input = NULL;
		GsfInputStdio  *in_stdio;
		GsfInputMemory *in_mem;
		GError *gerr = NULL;
		fprintf(stderr, "Inputfile:  %s\n", inputfile);
		gsf_init ();
		in_mem = gsf_input_mmap_new (inputfile, NULL);
		if (in_mem == NULL) {
			in_stdio = gsf_input_stdio_new(inputfile, &gerr);
			if(in_stdio != NULL)
				input = GSF_INPUT (in_stdio);
			else {
				fprintf(stderr, _("Could not open gsf input file."));
				fprintf(stderr, "\n");
				g_object_unref (G_OBJECT (input));
				exit(1);
			}
		} else {
			input = GSF_INPUT (in_mem);
		}
		if(0 > PX_open_gsf(pxdoc, input)) {
			fprintf(stderr, _("Could not open input file."));
			fprintf(stderr, "\n");
			exit(1);
		}
	} else {
#endif
		if(0 > PX_open_file(pxdoc, inputfile)) {
			fprintf(stderr, _("Could not open input file."));
			fprintf(stderr, "\n");
			exit(1);
		}
#ifdef HAVE_GSF
	}
#endif

	/* Below this pointer inputfile isn't used anymore. */
	free(inputfile);
	/* }}} */

	/* Set various variables with values from the header. */
	pxh = pxdoc->px_head;
//	PX_get_value(pxdoc, "recordsize", &frecordsize);
//	recordsize = (int) frecordsize;
//	PX_get_value(pxdoc, "filetype", &ffiletype);
//	filetype = (int) ffiletype;

	/* Decrypt or encrypt the file {{{
	 */
	if(encrypt) {
		float number;
		long headersize, blocksize;
		long encryption;
		int blockcount, blockno;
		char *block, *header;
		int ret;
		if(pxh->px_encryption) {
			fprintf(stderr, _("Input file is already encrypted."));
			fprintf(stderr, "\n");
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		encryption = px_passwd_checksum(password);
		fprintf(stderr, "encryption is 0x%X\n", encryption);
		PX_get_value(pxdoc, "headersize", &number);
		headersize = (int) number;
		if((header = (char *) pxdoc->malloc(pxdoc, headersize, _("Could not allocate memory for header of input file."))) == NULL) {
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		if(pxdoc->seek(pxdoc, pxdoc->px_stream, 0, SEEK_SET) < 0) {
			fprintf(stderr, _("Could not seek start of input file."));
			fprintf(stderr, "\n");
			pxdoc->free(pxdoc, header);
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		if((ret = pxdoc->read(pxdoc, pxdoc->px_stream, headersize, header)) < 0) {
			fprintf(stderr, _("Could not read header of input file."));
			fprintf(stderr, "\n");
			pxdoc->free(pxdoc, header);
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		put_long_le((char *)&header[0x25], encryption);
		put_long_le((char *)&header[0x5C], encryption);

		if(headersize != fwrite(header, 1, headersize, outfp)) {
			fprintf(stderr, _("Could not write header to output file."));
			fprintf(stderr, "\n");
			pxdoc->free(pxdoc, header);
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		pxdoc->free(pxdoc, header);

		PX_get_value(pxdoc, "maxtablesize", &number);
		blocksize = (int) number * 0x400;
		if((block = (char *) pxdoc->malloc(pxdoc, blocksize, _("Could not allocate memory for block of input file."))) == NULL) {
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		PX_get_value(pxdoc, "numblocks", &number);
		blockcount = (int) number;
		blockcount = pxh->px_fileblocks;
		fprintf(stderr, "file has %d blocks\n", blockcount);
		for(blockno=1; blockno<=blockcount; blockno++) {
			fprintf(stderr, "Reading block %d\n", blockno);
			if((ret = pxdoc->read(pxdoc, pxdoc->px_stream, blocksize, block)) < 0) {
				fprintf(stderr, _("Could not block of input file."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			fprintf(stderr, "Writing block %d\n", blockno);
			px_encrypt_db_block(block, block, encryption, blocksize, blockno);
			if(blocksize != fwrite(block, 1, blocksize, outfp)) {
				fprintf(stderr, _("Could not write block to output file."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
		}

	} else if(decrypt) {
		float number;
		long headersize, blocksize;
		long encryption;
		int blockcount, blockno;
		char *block, *header;
		int ret;
		if(!pxh->px_encryption) {
			fprintf(stderr, _("Input file is not encrypted."));
			fprintf(stderr, "\n");
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		encryption = pxh->px_encryption;

		PX_get_value(pxdoc, "headersize", &number);
		headersize = (int) number;
		if((header = (char *) pxdoc->malloc(pxdoc, headersize, _("Could not allocate memory for header of input file."))) == NULL) {
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		if(pxdoc->seek(pxdoc, pxdoc->px_stream, 0, SEEK_SET) < 0) {
			fprintf(stderr, _("Could not seek start of input file."));
			fprintf(stderr, "\n");
			pxdoc->free(pxdoc, header);
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		if((ret = pxdoc->read(pxdoc, pxdoc->px_stream, headersize, header)) < 0) {
			fprintf(stderr, _("Could not read header of input file."));
			fprintf(stderr, "\n");
			pxdoc->free(pxdoc, header);
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		put_long_le((char *)&header[0x25], 0);
		put_long_le((char *)&header[0x5C], 0);

		if(headersize != fwrite(header, 1, headersize, outfp)) {
			fprintf(stderr, _("Could not write header to output file."));
			fprintf(stderr, "\n");
			pxdoc->free(pxdoc, header);
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		pxdoc->free(pxdoc, header);

		PX_get_value(pxdoc, "maxtablesize", &number);
		blocksize = (int) number * 0x400;
		if((block = (char *) pxdoc->malloc(pxdoc, blocksize, _("Could not allocate memory for block of input file."))) == NULL) {
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		PX_get_value(pxdoc, "numblocks", &number);
		blockcount = (int) number;
		blockcount = pxh->px_fileblocks;
		fprintf(stderr, "file has %d blocks\n", blockcount);
		for(blockno=1; blockno<=blockcount; blockno++) {
			fprintf(stderr, "Reading block %d\n", blockno);
			if((ret = pxdoc->read(pxdoc, pxdoc->px_stream, blocksize, block)) < 0) {
				fprintf(stderr, _("Could not block of input file."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			fprintf(stderr, "Writing block %d\n", blockno);
			px_decrypt_db_block(block, block, encryption, blocksize, blockno);
			if(blocksize != fwrite(block, 1, blocksize, outfp)) {
				fprintf(stderr, _("Could not write block to output file."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
		}
	}

	fclose(outfp);
	PX_close(pxdoc);
	/* }}} */

	/* Free resources and close files {{{
	 */
	PX_close(pxdoc);
	PX_delete(pxdoc);

#ifdef HAVE_GSF
	if(PX_has_gsf_support() && usegsf) {
		gsf_shutdown();
	}
#endif
	/* }}} */

#ifdef MEMORY_DEBUGGING
	PX_mp_list_unfreed();
#endif

	exit(0);
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
