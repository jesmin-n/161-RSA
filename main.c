#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rsa.h"

static int usage(FILE *fp)
{
	return fprintf(fp,
"Usage:\n"
"  rsa encrypt <keyfile> <message>\n"
"  rsa decrypt <keyfile> <ciphertext>\n"
"  rsa genkey <numbits>\n"
	);
}

/* Encode the string s into an integer and store it in x. We're assuming that s
 * does not have any leading \x00 bytes (otherwise we would have to encode how
 * many leading zeros there are). */
static void encode(mpz_t x, const char *s)
{
	mpz_import(x, strlen(s), 1, 1, 0, 0, s);
}

/* Decode the integer x into a NUL-terminated string and return the string. The
 * returned string is allocated using malloc and it is the caller's
 * responsibility to free it. If len is not NULL, store the length of the string
 * (not including the NUL terminator) in *len. */
static char *decode(const mpz_t x, size_t *len)
{
	void (*gmp_freefunc)(void *, size_t);
	size_t count;
	char *s, *buf;

	buf = mpz_export(NULL, &count, 1, 1, 0, 0, x);

	s = malloc(count + 1);
	if (s == NULL)
		abort();
	memmove(s, buf, count);
	s[count] = '\0';
	if (len != NULL)
		*len = count;

	/* Ask GMP for the appropriate free function to use. */
	mp_get_memory_functions(NULL, NULL, &gmp_freefunc);
	gmp_freefunc(buf, count);

	return s;
}

/* The "encrypt" subcommand.
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int encrypt_mode(const char *key_filename, const char *message)
{
	struct rsa_key *key = (struct rsa_key *)malloc(sizeof(struct rsa_key));
	rsa_key_init(key); // initialize key structure
	if (rsa_key_load_public(key_filename, key) == -1) { // load private key from file
		return 1; // key error
	}
	mpz_t m, encrypt_m;
	mpz_init(m);
	mpz_init(encrypt_m);
	encode(m, message); // encode message and store into m
	rsa_encrypt(encrypt_m, m, key); // encrypt m based on key (from file) and store in encrypt_m

	gmp_printf("%Zd\n", encrypt_m);

	rsa_key_clear(key);
	mpz_clear(m);
	mpz_clear(encrypt_m);
	free(key);
	
	return 0;
}

/* The "decrypt" subcommand. c_str should be the string representation of an
 * integer ciphertext.

 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int decrypt_mode(const char *key_filename, const char *c_str)
{
	struct rsa_key *key = (struct rsa_key *)malloc(sizeof(struct rsa_key));
	rsa_key_init(key); // initialize key structure
	int check = rsa_key_load_private(key_filename, key); // load private key from file
	if (check == -1) {
		return 1; // key error
	}

	mpz_t cipher, decrypt_m;
	mpz_init(cipher);
	mpz_init(decrypt_m);
	mpz_set_str(cipher, c_str, 10); // load cipher text into mpz_t cipher
	rsa_decrypt(decrypt_m, cipher, key); // decrypt cipher based on key (from file) and store in decrypt_m

	size_t *length = (size_t *)malloc(sizeof(size_t));
	char *message = decode(decrypt_m, length);

	//don't do \n! it appropriatepends 0a to all outputs -_-
	fprintf(stdout, "%s", message); // print message
	free(message);
	rsa_key_clear(key);
	mpz_clear(cipher);
	mpz_clear(decrypt_m);
	free(key);
	
	return 0;
}

/* The "genkey" subcommand. numbits_str should be the string representation of
 * an integer number of bits (e.g. "1024").
 *
 * The return value is the exit code of the program as a whole: nonzero if there
 * was an error; zero otherwise. */
static int genkey_mode(const char *numbits_str)
{
	if (numbits_str == NULL) {
		return 1; // error
	}
	struct rsa_key *key = (struct rsa_key *)malloc(sizeof(struct rsa_key));
	rsa_key_init(key); // initialize key structure
	rsa_genkey(key, atoi(numbits_str));
	FILE* fp = fopen("tmpkey.priv", "w");
	rsa_key_write(fp, key);
	rsa_key_clear(key);
	fclose(fp);

	return 0;
}

int main(int argc, char *argv[])
{
	const char *command;

	if (argc < 2) {
		usage(stderr);
		return 1;
	}
	command = argv[1];

	if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "help") == 0) {
		usage(stdout);
		return 0;
	} else if (strcmp(command, "encrypt") == 0) {
		const char *key_filename, *message;

		if (argc != 4) {
			fprintf(stderr, "encrypt needs a key filename and a message\n");
			return 1;
		}
		key_filename = argv[2];
		message = argv[3];

		return encrypt_mode(key_filename, message);
	} else if (strcmp(command, "decrypt") == 0) {
		const char *key_filename, *c_str;

		if (argc != 4) {
			fprintf(stderr, "decrypt needs a key filename and a ciphertext\n");
			return 1;
		}
		key_filename = argv[2];
		c_str = argv[3];

		return decrypt_mode(key_filename, c_str);
	} else if (strcmp(command, "genkey") == 0) {
		const char *numbits_str;

		if (argc != 3) {
			fprintf(stderr, "genkey needs a number of bits\n");
			return 1;
		}
		numbits_str = argv[2];

		return genkey_mode(numbits_str);
	}

	usage(stderr);
	return 1;
}
