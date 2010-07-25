#include <xar/xar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("xar [target]\n");
		return 1;
	}

	xar_t pkg = xar_open(argv[1], READ);
	if (pkg == NULL) {
		printf("unable to open pkg\n");
		return 1;
	}

	// The first signature of the file is the one we're interested in.
	xar_signature_t sig = xar_signature_first(pkg);

	// Get the signature type
	const char *type = xar_signature_type(sig);
	printf("Signature Type = %s\n", type);

	if (strcmp(type, "RSA")) {
		printf("Not RSA\n");
		return 1;
	}

	// Extract the certificate chain
	int32_t ncerts = xar_signature_get_x509certificate_count(sig);
	X509 **certs = alloca(sizeof(X509 *) * ncerts);
	for (int32_t i = 0; i < ncerts; i++) {
		// Get the certificate data...
		const uint8_t *data = NULL;
		uint32_t len;
		if (xar_signature_get_x509certificate_data(sig, i, &data, &len) == -1) {
			printf("unable to extarct x509 cert data\n");
			return 1;
		}
		X509 *cert = d2i_X509(NULL, &data, (int)len);
		if (cert == NULL) {
			printf("unable to import cert data..\n");
			return 1;
		}
		certs[i] = cert;
	}

	// Extract the TOC signed data
	uint8_t *plaindata = NULL, *signdata = NULL;
	uint32_t plainlen = 0, signlen = 0;
	off_t signoff = 0;
	if (xar_signature_copy_signed_data(sig, &plaindata, &plainlen, &signdata, &signlen, &signoff) != 0) {
		printf("failed to copy signed data...\n");
		return 1;
	}

	printf("plainlen = %u\n", plainlen);
	printf("signlen = %u\n", signlen);
	printf("signoff = %llu\n", signoff);

	if (plainlen == 20) { /* SHA1 */
		EVP_PKEY *pkey = X509_get_pubkey(certs[0]);
		if (! pkey) {
			printf("unable to get pubkey\n");
			return 1;
		}

		if (pkey->type != EVP_PKEY_RSA) {
			printf("pkey not rsa\n");
			return 1;
		}

		RSA *rsa = pkey->pkey.rsa;
		if (! rsa) {
			printf("no rsa ptr available\n");
			return 1;
		}

		// Verify the signed archive...
		int success = RSA_verify(NID_sha1, plaindata, plainlen, (unsigned char *)signdata, signlen, rsa);
		printf("success = %i\n", success);
	} else {
		printf("unhandled message digest algorithm used...\n");
		return 1;
	}

	return 0;
}
