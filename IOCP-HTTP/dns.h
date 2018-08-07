#ifndef __DNS_H
#define __DNS_H


#include "config.h"

typedef void(__stdcall* dns_callback)(void *ud, int state, char *ip);

#ifdef __cplusplus
extern "C" {
#endif

EXPORT void CALL gethostinfo(char *name, int cache,dns_callback cb, void *ud);
EXPORT int CALL dns_init();
EXPORT void CALL dns_uninit();

#ifdef __cplusplus
}
#endif
#endif
