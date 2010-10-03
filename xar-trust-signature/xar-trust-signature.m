#include <xar/xar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <Security/Security.h>
#import <Foundation/Foundation.h>

#define qWarning(s) printf(s "\n")

// Get the certificates form our installer XAR as a NSArray of SecCertificateRef's.
static bool getInstallerCerts(const char *path, NSArray **array) {
	bool ret = false;
	OSStatus err = noErr;
	xar_t pkg = NULL;
	xar_signature_t sig = NULL;
	int32_t ncerts = 0;
	const uint8_t *data = NULL;
	uint32_t len = 0;
	SecCertificateRef tmp = NULL;
	int cur = 0;

	if (array == NULL) {
		qWarning("getInstallerCerts: Argument error.");
		goto err;
	}

	pkg = xar_open(path, READ);
	if (pkg == NULL) {
		qWarning("getInstallerCerts: Unable to open pkg.");
		goto err;
	}

	// We're only interested in the first signature.
	sig = xar_signature_first(pkg);
	if (sig == NULL) {
		qWarning("getInstallerCerts: Unable to get first signature of XAR archive.");
		goto err;
	}

	ncerts = xar_signature_get_x509certificate_count(sig);
	*array = [[NSMutableArray alloc] init];
	for (int32_t i = 0; i < ncerts; i++) {
		if (xar_signature_get_x509certificate_data(sig, i, &data, &len) == -1) {
			qWarning("getInstallerCerts: Unable to extract certificate data.");
			goto err;
		}
		const CSSM_DATA crt = { (CSSM_SIZE) len, (uint8_t *) data };
		err = SecCertificateCreateFromData(&crt, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &tmp);
		[(NSMutableArray *) *array addObject:(id)tmp];
	}

	ret = true;
err:
	return ret;
}

// Validate the signature of a XAR archive (the archive format
// Apple uses for their installlers)
static bool validateInstallerSignature(const char *path) {
	xar_t pkg = NULL;
	xar_signature_t sig = NULL;
	const char *type = NULL;
	int32_t ncerts = 0;
	X509 **certs = NULL;
	const uint8_t *data = NULL;
	uint32_t len = 0;
	uint8_t *plaindata = NULL, *signdata = NULL;
	uint32_t plainlen = 0, signlen = 0;
	bool ret = false;
	int success = 0;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;

	// Open installer package.
	pkg = xar_open(path, READ);
	if (pkg == NULL) {
		qWarning("validateInstallerSignature: Unable to open installer for verification.");
		goto err;
	}

	// The first signature of the file is the one we're interested in.
	sig = xar_signature_first(pkg);
	if (sig == NULL) {
		qWarning("validateInstallerSignature: Unable to get first signature.");
		goto err;
	}

	// Get the signature type
	type = xar_signature_type(sig);
	if (strcmp(type, "RSA")) {
		qWarning("validateInstallerSignature: Signature not RSA.");
		goto err;
	}

	// Extract the certificate chain
	ncerts = xar_signature_get_x509certificate_count(sig);
	if (!(ncerts > 0)) {
		qWarning("validateInstallerSignature: No certificates found in XAR.");
		goto err;
	}

	certs = (X509 **)alloca(sizeof(X509 *) * ncerts);
	for (int32_t i = 0; i < ncerts; i++) {
		// Get the certificate data...
		if (xar_signature_get_x509certificate_data(sig, i, &data, &len) == -1) {
			qWarning("validateInstallerSignature:  Could not extract DER encoded certificate from XARchive.");
			goto err;
		}
		X509 *cert = d2i_X509(NULL, &data, (int)len);
		if (cert == NULL) {
			qWarning("validateInstallerSignature: Could not parse DER data.");
			goto err;
		}
		certs[i] = cert;
	}

	// Extract the TOC signed data
	if (xar_signature_copy_signed_data(sig, &plaindata, &plainlen, &signdata, &signlen) != 0) {
		qWarning("validateInstallerSignature: Could not get signed data from XARchive.");
		goto err;
	}

	if (plainlen != 20) { /* SHA1 */
		qWarning("validateInstallerSignature: Digest of installer is not SHA1, cannot verify.");
		goto err;
	}

	pkey = X509_get_pubkey(certs[0]);
	if (! pkey) {
		qWarning("validateInstallerSignature: Unable to get pubkey from X509 struct.");
		goto err;
	}

	if (pkey->type != EVP_PKEY_RSA) {
		qWarning("validateInstallerSignature: Public key is not RSA.");
		goto err;
	}

	rsa = pkey->pkey.rsa;
	if (! rsa) {
		qWarning("validateInstallerSignature: Could not get RSA data from pkey.");
		goto err;
	}

	// Verify the signed archive...
	success = RSA_verify(NID_sha1, plaindata, plainlen, (unsigned char *)signdata, signlen, rsa);
	ret = (success == 1);

err:
	for (int32_t i = 0; i < ncerts; i++) {
		if (certs[i] != NULL)
			X509_free(certs[i]);
	}
	free(plaindata);
	free(signdata);
	if (pkg)
		xar_close(pkg);
	return ret;
}

// First, validate the signature of the installer XAR archive. Then, check
// that the certificate chain is trusted by the system.
bool validateInstaller(const char *path) {
	bool ret = false;
	OSStatus err = noErr;
	NSArray *certs = nil;
	SecPolicySearchRef search = NULL;
	SecPolicyRef policy = NULL;
	SecTrustRef trust = NULL;
	SecTrustResultType result;
	CSSM_OID oid = CSSMOID_APPLE_X509_BASIC;

	// First, check that the archive signature is OK.
	if (! validateInstallerSignature(path)) {
		goto err;
	}

	// Get the certificate (and any intermediate certs) from the XAR archive.
	if (! getInstallerCerts(path, &certs)) {
		goto err;
	}

	// Create policy
	err = SecPolicySearchCreate(CSSM_CERT_X_509v3, &oid, NULL, &search);
	if (err != noErr) {
		qWarning("validateInstaller: Unable to create SecPolicySearch object.");
		goto err;
	}
	err = SecPolicySearchCopyNext(search, &policy);
	if (err != noErr) {
		qWarning("validateInstaller: Unable to fetch SecPolicyRef from search object.");
		goto err;
	}

	// Create trust
	err = SecTrustCreateWithCertificates((CFArrayRef)certs, policy, &trust);
	if (err != noErr) {
		qWarning("validateInstaller: Unable to create trust with certs...");
		goto err;
	}

	// Do we trust this certificate?
	err = SecTrustEvaluate(trust, &result);
	if (err != noErr) {
		qWarning("validateInstaller: Unable to evaulate trust..");
		goto err;
	}

	// Good documentation on the values of SecTrustResultType:
	// http://lists.apple.com/archives/apple-cdsa/2006/Apr/msg00013.html
	switch (result) {
		case kSecTrustResultProceed:     // User trusts this certificate (as well as the system)
		case kSecTrustResultConfirm:     // Check with the user before proceeding (which we're already doing by giving them a choice).
		case kSecTrustResultUnspecified: // No user trust setting for this cert.
			ret = true;
			break;

		default:
			printf("SecTrustEvaluate returned = %i\n", result);
			ret = false;
			break;
	}

err:
	[certs release];
	if (search)
		CFRelease(search);
	if (policy)
		CFRelease(policy);
	if (trust)
		CFRelease(trust);
	return ret;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("xar-trust-signature [target]\n");
		return 1;
	}

	bool b = validateInstaller(argv[1]);
	printf("success? %i\n", b);
	return 0;
}
