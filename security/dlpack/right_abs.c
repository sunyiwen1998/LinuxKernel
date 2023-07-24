// SPDX-License-Identifier: GPL-2.0-only

//权限抽象组所使用文件
#include "include/right_abs.h"
#include "include/dlpack.h"
#include "include/state.h"
#include "include/pattern.h"


//根据系统调用序列状态机判断是否要进行检查
int should_check(void)
{
	struct task_ctx *ctx;

	ctx = get_task_ctx(current);

	if (ctx->version < syscall_pattern_version) {
		task_free(ctx);
		task_init(ctx);
		ctx->version = syscall_pattern_version;
	}
	return (int) ctx->satisfied;
}

//初始化进程所拥有的rules
int init_proc_perm(struct task_ctx *ctx)
{
	ctx->pr = kmalloc(sizeof(*(ctx->pr)), GFP_KERNEL);
	INIT_LIST_HEAD(&ctx->pr->rules);
	return 0;
}

void free_proc_perm(struct task_ctx *ctx)
{
	kfree(ctx->pr);
}
