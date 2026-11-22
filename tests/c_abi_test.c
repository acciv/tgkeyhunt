#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/tgkeyhunt.h"

int main(void) {
    const char *text = "token 123456789:FAKE_9ZqX8wV7uT6sR5qP4oN3mL2kI1jH0gF";
    char *out = NULL;
    int len = 0;

    int rc = th_scan_text(text, "c-test.txt", &out, &len);
    if (rc != 0) {
        fprintf(stderr, "th_scan_text returned %d\n", rc);
        return 1;
    }
    if (out == NULL || len <= 0) {
        fprintf(stderr, "empty result\n");
        return 1;
    }
    if (strstr(out, "confidence") == NULL || strstr(out, "FAKE_9ZqX") != NULL) {
        fprintf(stderr, "unexpected result: %s\n", out);
        th_free(out);
        return 1;
    }

    printf("C ABI ok: %d bytes\n", len);
    th_free(out);
    return 0;
}
