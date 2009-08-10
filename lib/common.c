
#include <stdlib.h>
#include <glib.h>
#include <cld-private.h>
#include "cld_msg.h"

unsigned long long cld_sid2llu(const uint8_t *sid)
{
	const uint64_t *v_le = (const uint64_t *) sid;
	uint64_t v = le64_to_cpu(*v_le);
	return v;
}

void __cld_rand64(void *p)
{
	uint32_t *v = p;

	v[0] = rand();
	v[1] = rand();
}

