// SPDX-License-Identifier: GPL-2.0-only

#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include "include/dlpack.h"
#include "include/event.h"
#include "include/pattern.h"

struct fsm *dlpack_fsm;

struct lsm_blob_sizes dlpack_blob_sizes __lsm_ro_after_init = {
	.lbs_task = sizeof(struct task_ctx),
};

/**
 * dlpack_task_alloc - 进程空间分配钩函数
 * @task: 进程 task_struct
 * @clone_flags: clone 标志
 *
 * Return:
 *   0: 成功
 *   Others: 失败
 */
static int dlpack_task_alloc(struct task_struct *task,
			     unsigned long clone_flags)
{
	struct task_ctx *ctx = get_task_ctx(task);
	struct task_ctx *old_ctx = get_task_ctx(current);
	int ret = 1;

	ret = init_proc_perm(ctx);
	if (ret != 0)
		return ret;

	ret = copy_task_waiting(ctx, old_ctx);
	if (ret != 0)
		return ret;

	return ret;
}

/**
 * dlpack_task_free - 进程释放钩函数
 * @task: 进程 task_struct
 *
 * Return:
 *   void
 */
static void dlpack_task_free(struct task_struct *task)
{
	struct task_ctx *ctx = get_task_ctx(task);

	task_free(ctx);
	free_proc_perm(ctx);
}


/**
 * dlpack_file_permission - file_permission 钩函数
 * @file: 文件
 * @mask: 权限 mask
 *
 * Return:
 *   0 
 */
static int dlpack_file_permission(struct file *file, int mask)
{
	if (mask == MAY_READ) {
		process_syscall(get_task_ctx(current), "E_SP_READ");
	}
	if (mask == MAY_WRITE) {
		process_syscall(get_task_ctx(current), "E_SP_WRITE");
	}
	return 0;
}

static int dlpack_socket_create(int family, int type, int protocol, int kern)
{
	process_syscall(get_task_ctx(current), "E_SP_SOCKET");
	return 0;
}

static int dlpack_socket_connect(struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
	process_syscall(get_task_ctx(current), "E_SP_CONNECT");
	return 0;
}

static struct security_hook_list dlpack_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(task_alloc, dlpack_task_alloc),
	LSM_HOOK_INIT(task_free, dlpack_task_free),
	LSM_HOOK_INIT(file_ioctl, dlpack_file_ioctl),
	LSM_HOOK_INIT(file_open, dlpack_file_open),
	LSM_HOOK_INIT(file_permission, dlpack_file_permission),
	LSM_HOOK_INIT(socket_create, dlpack_socket_create),
	LSM_HOOK_INIT(socket_connect, dlpack_socket_connect),
};

/**
 * set_init_ctx - 初始化进程安全上下文
 *
 * Return:
 *   0: 成功
 */
static int __init set_init_ctx(void)
{
	struct task_ctx *ctx = get_task_ctx(current);

	init_proc_perm(ctx);
	task_init(ctx);
	return 0;
}

/**
 * dlpack_init - dlpack 安全模块初始化函数
 *
 * Return:
 *   0: 成功
 */
static int __init dlpack_init(void)
{
	dlpack_info("Initializing.");

	INIT_LIST_HEAD(&sysp_rules);
	init_global_fsm();
	init_states();
	init_trie();
	init_events();
	set_init_ctx();
	security_add_hooks(dlpack_hooks, ARRAY_SIZE(dlpack_hooks), "dlpack");

	dlpack_info("Initialized.");
	return 0;
}

DEFINE_LSM(dlpack) = {
	.name = "dlpack",
	.blobs = &dlpack_blob_sizes,
	.init = dlpack_init,
};
