#ifndef __CHUNK_PRIVATE_H__
#define __CHUNK_PRIVATE_H__

#include <stdint.h>
#include <glib.h>

static inline uint16_t le16_to_cpu(uint16_t val)
{
	return GUINT16_FROM_LE(val);
}

static inline uint16_t cpu_to_le16(uint16_t val)
{
	return GUINT16_TO_LE(val);
}

static inline uint32_t le32_to_cpu(uint32_t val)
{
	return GUINT32_FROM_LE(val);
}

static inline uint32_t cpu_to_le32(uint32_t val)
{
	return GUINT32_TO_LE(val);
}

static inline uint64_t le64_to_cpu(uint64_t val)
{
	return GUINT64_FROM_LE(val);
}

static inline uint64_t cpu_to_le64(uint64_t val)
{
	return GUINT64_TO_LE(val);
}

#endif /* __CHUNK_PRIVATE_H__ */
