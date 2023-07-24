/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _DLPACK_ACTION_H
#define _DLPACK_ACTION_H

void entry_print_state(void *arg);
void exit_print_state(void *arg);
void exit_odd_deny(void *arg);
void exit_even_access(void *arg);

#endif /* _DLPACK_ACTION_H */
