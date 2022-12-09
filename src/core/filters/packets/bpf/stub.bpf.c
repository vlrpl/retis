/* SPDX-License-Identifier: GPL-2.0 */
#include <packet-filter.h>

__attribute__ ((noinline))
int packet_filter(struct filter_context *ctx)
{
	return (volatile int)0;
}
