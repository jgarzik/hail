#ifndef __CHUNK_PRIVATE_H__
#define __CHUNK_PRIVATE_H__

/*
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

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

#define MDB_TPATH_FMT	"%s/%X"
#define BAD_TPATH_FMT	"%s/bad"
#define PREFIX_LEN 3

#endif /* __CHUNK_PRIVATE_H__ */
