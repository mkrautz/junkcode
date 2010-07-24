#include <xar/xar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

	int allgood = 1;
	int32_t foundcerts = 0;
	xar_signature_t sig = xar_signature_first(pkg);
	while (sig != NULL && allgood == 1) {
		int32_t ncerts = xar_signature_get_x509certificate_count(sig);
		for (int32_t i = 0; i < ncerts; i++) {
			const uint8_t *data = NULL;
			uint32_t len;
			if (xar_signature_get_x509certificate_data(sig, i, &data, &len) == -1) {
				allgood = 0;
				break;
			}
			char buf[1024];
			memset(buf, 0, 1024);
			int nwritten = snprintf(buf, 1024, "%i.cert", foundcerts);
			if (nwritten > 1024) {
				allgood = 0;
				break;
			}
			FILE *f = fopen(buf, "w");
			fwrite(data, 1, len, f);
			fclose(f);
			printf("wrote cert data to %s\n", buf);
			++foundcerts;
		}
		if (allgood == 0)
			break;
		sig = xar_signature_next(sig);
	}

	printf("allgood = %i\n", allgood);
	printf("foundcerts = %i\n", foundcerts);

	return 0;
}
