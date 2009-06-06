
#include <glib.h>
#include "cld_msg.h"

unsigned long long sid2llu(const uint8_t *sid)
{
	const uint64_t *v_le = (const uint64_t *) sid;
	uint64_t v = GUINT64_FROM_LE(*v_le);
	return v;
}

