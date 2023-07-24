// SPDX-License-Identifier: GPL-2.0-only
#include <linux/types.h>
#include "include/dlpack.h"

unsigned int hash(const char *__kernel key)
{
	const char *p;
	size_t size;
	unsigned int val;

	BUG_ON(NULL == key);

	val = 0;
	size = strlen(key);
	for (p = key; (p - key) < size; p++)
		val = (val << 4 | (val >> (8 * sizeof(unsigned int) - 4))) ^ (*p);
	return val;
}
