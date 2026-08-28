/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr port shim: empty stub for dup2().
 *
 * Zephyr's POSIX layer provides dup() (see lib/os/fdtable.c) but not
 * dup2() - the upstream dup2() implementation was reverted before v3.7
 * (zephyrproject-rtos/zephyr#75205, #75244).  Keep a failing stub for
 * dup2() so the build stays linkable if anything still references it.
 */

#include <errno.h>
#include <unistd.h>

#ifdef __ZEPHYR__
#include <zephyr/sys/printk.h>
#endif

int dup2(int oldfd, int newfd)
{
    (void)oldfd;
    (void)newfd;
#ifdef __ZEPHYR__
    printk("dup2(%d, %d) not supported on Zephyr, returning -1\n", oldfd,
           newfd);
#endif
    errno = ENOSYS;
    return -1;
}
