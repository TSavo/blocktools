/* blocktools C ABI (secrets-off). Public data only: no private keys, no network.
 * Strings returned by bt_chain_table / bt_envelope are heap-allocated UTF-8;
 * free them with bt_free. bt_version returns a static string (do not free).
 */
#ifndef BLOCKTOOLS_H
#define BLOCKTOOLS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Library version string, e.g. "0.1.0". Static; do not free. */
const char *bt_version(void);

/* JSON array of chain registry rows (same as chain-table --array). Caller frees with bt_free. */
char *bt_chain_table(void);

/* Run a blocktools.sign/v1 envelope request (JSON object). Returns a JSON object string.
 * Caller frees with bt_free. Never returns NULL (on OOM may abort via Rust alloc). */
char *bt_envelope(const char *json_utf8);

/* Free a string returned by bt_chain_table or bt_envelope. NULL is a no-op. */
void bt_free(char *p);

#ifdef __cplusplus
}
#endif

#endif /* BLOCKTOOLS_H */
