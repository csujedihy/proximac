// key = string to match or null
// klen = key length (or 0), or if null key then len is the array offset value
// json = json object or array
// jlen = length of json
// vlen = where to store return value length
// returns pointer to value and sets len to value length, or 0 if not found
// any parse error will set vlen to the position of the error
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
const char *js0n(const char *key, size_t klen,
				 const char *json, size_t jlen, size_t *vlen);
#ifdef __cplusplus
} /* extern "C" */
#endif
