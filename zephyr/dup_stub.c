/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr port shim: empty stubs for dup()/dup2().
 *
 * Zephyr's POSIX layer does not provide dup()/dup2() - the upstream
 * implementation was reverted before v3.7 due to an unrelated regression
 * (zephyrproject-rtos/zephyr#75205, #75244). bmcweb links against these
 * symbols on Linux, so provide failing stubs here to keep the Zephyr build
 * linkable. Functionality is intentionally not implemented.
 */

#include <errno.h>
#include <unistd.h>

#ifdef __ZEPHYR__
#include <zephyr/sys/printk.h>
#endif

int dup(int fd)
{
    (void)fd;
#ifdef __ZEPHYR__
    printk("dup(%d) not supported on Zephyr, returning -1\n", fd);
#endif
    errno = ENOSYS;
    return -1;
}

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
