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
	if(!strcmp(progname, "pxencrypt")) {
		printf(_("%s encrypts a paradox file."), progname);
	} else if(!strcmp(progname, "pxdecrypt")) {
		printf(_("%s decrypts a paradox file."), progname);
	} else {
		printf(_("%s decrypts or encrypts a paradox file."), progname);
	}
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
	printf(_("  --database-file=FILE .db file if en/decrypting .mb files."));
	printf("\n");
#ifdef HAVE_GSF
	if(PX_has_gsf_support()) {
		printf(_("  --use-gsf           use gsf library to read input file."));
		printf("\n");
	}
#endif
	printf("\n");
	printf(_("  -o, --output-file=FILE output data into file instead of stdout."));
	if(!strcmp(progname, "pxcrypt")) {
		printf("\n\n");
		printf(_("Options to select mode:"));
		printf("\n");
		printf(_("  --mode=MODE         set operation mode (encrypt, decrypt)."));
		printf("\n");
		printf(_("  -e, --encrypt       encrypt file."));
		printf("\n");
		printf(_("  -d, --decrypt       decrypt file."));
	}

	if(strcmp(progname, "pxdecrypt")) {
		printf("\n\n");
		printf(_("Encryption options:"));
		printf("\n");
		printf(_("  --password=WORD     set password for encryption."));
	}

	printf("\n\n");
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
	int decrypt = 0, encrypt = 0, guess = 0;
	int usegsf = 0;
	int verbose = 0;
	char *password = NULL;
	char *inputfile = NULL;
	char *outputfile = NULL;
	char *dbfile = NULL;
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
			{"guess", 0, 0, 'g'},
			{"output-file", 1, 0, 'o'},
			{"database-file", 1, 0, 1},
			{"password", 1, 0, 'p'},
			{"help", 0, 0, 'h'},
			{"mode", 1, 0, 4},
			{"use-gsf", 0, 0, 8},
			{"version", 0, 0, 11},
			{0, 0, 0, 0}
		};
		c = getopt_long (argc, argv, "vedghp:o:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
			case 1:
				dbfile = strdup(optarg);
				break;
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
			case 'g':
				guess = 1;
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
	if(decrypt == 0 && encrypt == 0 && guess == 0)
		decrypt = 1;

	if(encrypt && !password && !dbfile) {
		fprintf(stderr, _("Encryption mode requires a password."));
		fprintf(stderr, "\n");
		usage(progname);
		exit(1);
	}

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

	if(!dbfile)
		dbfile = inputfile;

#ifdef HAVE_GSF
	if(PX_has_gsf_support() && usegsf) {
		GsfInput *input = NULL;
		GsfInputStdio  *in_stdio;
		GsfInputMemory *in_mem;
		GError *gerr = NULL;
		fprintf(stderr, "Inputfile:  %s\n", dbfile);
		gsf_init ();
		in_mem = gsf_input_mmap_new (dbfile, NULL);
		if (in_mem == NULL) {
			in_stdio = gsf_input_stdio_new(dbfile, &gerr);
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
		if(0 > PX_open_file(pxdoc, dbfile)) {
			fprintf(stderr, _("Could not open input file."));
			fprintf(stderr, "\n");
			exit(1);
		}
#ifdef HAVE_GSF
	}
#endif

	/* Below this pointer dbfile isn't used anymore. */
	free(dbfile);
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
		/* check if input file is a .db or .mb file */
		if(dbfile == inputfile) {
			if(pxh->px_encryption) {
				fprintf(stderr, _("Input file is already encrypted."));
				fprintf(stderr, "\n");
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			encryption = px_passwd_checksum(password);
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
			if(verbose) {
				fprintf(stderr, _("File has %d data blocks."), blockcount);
				fprintf(stderr, "\n");
			}
			for(blockno=1; blockno<=blockcount; blockno++) {
				if((ret = pxdoc->read(pxdoc, pxdoc->px_stream, blocksize, block)) < 0) {
					fprintf(stderr, _("Could not read block from input file."));
					fprintf(stderr, "\n");
					pxdoc->free(pxdoc, header);
					PX_close(pxdoc);
					fclose(outfp);
					exit(1);
				}
				if(verbose) {
					fprintf(stderr, _("Writing block %d."), blockno);
					fprintf(stderr, "\n");
				}
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
		} else {
			if(!pxh->px_encryption) {
				fprintf(stderr, _("Database file is not encrypted."));
				fprintf(stderr, "\n");
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			/* Set encryption of .db file to 0, because the the .mb file
			 * needs to be read without decryption.
			 */
			encryption = pxh->px_encryption;
			pxh->px_encryption = 0;
			if(NULL == (pxblob = PX_new_blob(pxdoc))) {
				fprintf(stderr, _("Could not create new blob file object."));
				fprintf(stderr, "\n");
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			if(0 > PX_open_blob_file(pxblob, inputfile)) {
				fprintf(stderr, _("Could not open blob file."));
				fprintf(stderr, "\n");
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			blocksize = 0x1000;
			if((block = (char *) pxdoc->malloc(pxdoc, blocksize, _("Could not allocate memory for block of input file."))) == NULL) {
				PX_close(pxdoc);
				PX_close_blob(pxblob);
				fclose(outfp);
				exit(1);
			}
			if(pxblob->seek(pxblob, pxblob->mb_stream, 0, SEEK_SET) < 0) {
				fprintf(stderr, _("Could not fseek start of blob file."));
				fprintf(stderr, "\n");
				PX_close(pxdoc);
				PX_close_blob(pxblob);
				fclose(outfp);
				exit(1);
			}
			while(pxblob->read(pxblob, pxblob->mb_stream, blocksize, block) > 0) {
				px_encrypt_mb_block(block, block, encryption, blocksize);
				if(blocksize != fwrite(block, 1, blocksize, outfp)) {
					fprintf(stderr, _("Could not write block to output file."));
					fprintf(stderr, "\n");
					PX_close(pxdoc);
					PX_close_blob(pxblob);
					fclose(outfp);
					exit(1);
				}
			}
			PX_close_blob(pxblob);
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

		/* check if input file is a .db or .mb file */
		if(dbfile == inputfile) {
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
			if(verbose) {
				fprintf(stderr, _("File has %d data blocks."), blockcount);
				fprintf(stderr, "\n");
			}
			for(blockno=1; blockno<=blockcount; blockno++) {
				if((ret = pxdoc->read(pxdoc, pxdoc->px_stream, blocksize, block)) < 0) {
					fprintf(stderr, _("Could not read block from input file."));
					fprintf(stderr, "\n");
					pxdoc->free(pxdoc, header);
					PX_close(pxdoc);
					fclose(outfp);
					exit(1);
				}
				/* No need to decrypt, because pxdoc->read() has already done it. */
				if(blocksize != fwrite(block, 1, blocksize, outfp)) {
					fprintf(stderr, _("Could not write block to output file."));
					fprintf(stderr, "\n");
					pxdoc->free(pxdoc, header);
					PX_close(pxdoc);
					fclose(outfp);
					exit(1);
				}
			}
		} else {
			int ret;
			if(NULL == (pxblob = PX_new_blob(pxdoc))) {
				fprintf(stderr, _("Could not create new blob file object."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			if(0 > PX_open_blob_file(pxblob, inputfile)) {
				fprintf(stderr, _("Could not open blob file."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				fclose(outfp);
				exit(1);
			}
			blocksize = 0x1000;
			if((block = (char *) pxdoc->malloc(pxdoc, blocksize, _("Could not allocate memory for block of input file."))) == NULL) {
				PX_close(pxdoc);
				PX_close_blob(pxblob);
				fclose(outfp);
				exit(1);
			}
			if(pxblob->seek(pxblob, pxblob->mb_stream, 0, SEEK_SET) < 0) {
				fprintf(stderr, _("Could not fseek start of blob file."));
				fprintf(stderr, "\n");
				pxdoc->free(pxdoc, header);
				PX_close(pxdoc);
				PX_close_blob(pxblob);
				fclose(outfp);
				exit(1);
			}
			while((ret = pxblob->read(pxblob, pxblob->mb_stream, blocksize, block)) > 0) {
				/* No need to decrypt because pxblob->read() does it for us */
				if(blocksize != fwrite(block, 1, blocksize, outfp)) {
					fprintf(stderr, _("Could not write block to output file."));
					fprintf(stderr, "\n");
					pxdoc->free(pxdoc, header);
					PX_close(pxdoc);
					PX_close_blob(pxblob);
					fclose(outfp);
					exit(1);
				}
			}
			PX_close_blob(pxblob);
		}
	} else if(guess) {
#define FIRSTCHAR 48
#define LASTCHAR 127
		long encryption;
		int i0, i1, i2, i3, i4, i5, i6, i7;
		char password[9] = "        ";
		if(!pxh->px_encryption) {
			fprintf(stderr, _("Input file is not encrypted."));
			fprintf(stderr, "\n");
			PX_close(pxdoc);
			fclose(outfp);
			exit(1);
		}
		encryption = pxh->px_encryption;
		password[8] = '\0';
		for(i0=FIRSTCHAR; i0<=LASTCHAR; i0++) {
			password[0] = (char) i0;
			for(i1=FIRSTCHAR; i1<=LASTCHAR; i1++) {
				password[1] = (char) i1;
				for(i2=FIRSTCHAR; i2<=LASTCHAR; i2++) {
					password[2] = (char) i2;
					for(i3=FIRSTCHAR; i3<=LASTCHAR; i3++) {
						password[3] = (char) i3;
						for(i4=FIRSTCHAR; i4<=LASTCHAR; i4++) {
							password[4] = (char) i4;
							for(i5=FIRSTCHAR; i5<=LASTCHAR; i5++) {
								password[5] = (char) i5;
								for(i6=FIRSTCHAR; i6<=LASTCHAR; i6++) {
									password[6] = (char) i6;
									for(i7=FIRSTCHAR; i7<=LASTCHAR; i7++) {
										password[7] = (char) i7;
										if(encryption == px_passwd_checksum(password )) {
											fprintf(stdout, "%s\n", password);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	fclose(outfp);
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
