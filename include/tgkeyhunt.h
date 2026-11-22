#ifndef TGKEYHUNT_H
#define TGKEYHUNT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Scans a text buffer for Telegram Bot API token candidates.
 * Returns 0 on success, 1 on error. The result string must be released
 * with th_free(). The secret itself is never written to the result.
 */
int th_scan_text(const char *text, const char *file, char **out_json, int *out_len);

/* Releases a string allocated by th_scan_text. */
void th_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
