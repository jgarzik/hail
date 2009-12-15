#ifndef __CLD_COMMON_H__
#define __CLD_COMMON_H__

#include <stdint.h>

unsigned long long cld_sid2llu(const uint8_t *sid);
void __cld_rand64(void *p);
const char *cld_errstr(enum cle_err_codes ecode);
int cld_readport(const char *fname);

#endif /* __CLD_COMMON_H__ */
