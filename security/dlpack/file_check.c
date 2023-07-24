#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/string.h>

#include "include/dl_policy.h"
#include "include/dlpack.h"
#include "include/pattern.h"
#include "include/right_abs.h"
#include "include/state.h"

/**
 * get_file_path - 获取文件路径
 * @file: 内核描述一个打开的文件的结构体
 *
 * Return:
 *   Path: 文件绝对路径
 */
static char *get_file_path(struct file *file) {
  char *path, *buff;
  if (!file) {
    dlpack_err("can't get file path for NULL file");
    return NULL;
  }

  buff = (char *)__get_free_page(SLAB_TEMPORARY);
  if (!buff) {
    dlpack_err("allocating buffer failed");
    return NULL;
  }

  path = d_path(&file->f_path, buff, PAGE_SIZE);
  if (IS_ERR(path)) {
    dlpack_err("failed");
    free_page(buff);
    return NULL;
  }
  return path;
}

/**
 * get_proc_rules - 获取进程的rules链表
 *
 * Return:
 *   &ctx->pr->rules: 进程的rule链表
 */
inline struct list_head *get_proc_rules(void) {
  return &get_task_ctx(current)->pr->rules;
}

/**
 * rules_check - 判断进程是否拥有执行当前操作的rules
 * @path: 文件绝对路径
 *
 * Return:
 *   0: 成功
 *   -1: 失败
 */
static int rules_check(char *path) {
  // get rules owned by current process
  struct list_head *proc_rule = get_proc_rules();

  if (list_empty(proc_rule))
    dlpack_debug("current proc doesn't have any rule");

  // check if the process has this rule
  if (find_file_rule(proc_rule, RULE_FILE, path, 4) == -1)
    return -1;

  // yes it has!
  return 0;
}

/**
 * state_check - 判断当前环境（state）是否允许执行当前操作
 * @path: 文件绝对路径
 * @type: 0表示cap，1表示file，2表示ioctl
 * @limits:
 *
 * Return:
 *   0: 成功
 *   -1: 失败
 */
static int state_check(char *path, int type, unsigned int limits) {
  struct fsm_state *state = get_global_state();
  dlpack_debug("state id is: %d", state->id);

  if (list_empty(&state->rule_head)) {
    dlpack_debug("current state doesn't alow any rule");
  }

  // check if current state alows this rule
  if (state->id == 1 << MAX_STATE_LEN) {
    dlpack_debug("not concerned state: %d", state->id);
    return 0;
  } else if (type == RULE_FILE &&
             find_file_rule(&state->rule_head, 1, path, limits) == -1) {
    dlpack_debug("file rule not allowed in state : %d", state->id);
    return -1;
  } else if (type == RULE_IOCTL &&
             find_ioctl_rule(&state->rule_head, 1, path, limits) == -1) {
    dlpack_info("ioctl rule not allowed in state: %d", state->id);
    return -1;
  }

  // dlpack_info("rule matched in state : %d", state->id);
  return 0;
}

static int do_sysp_check(uint64_t sysrep, int type, const char *path, int limits) {
  struct dl_rule *rule;
	if (get_task_ctx(current)->version < syscall_pattern_version) {
    return 0;
  }
  for_each_rule(rule, &sysp_rules) {
    if ((sysrep & (1ULL << rule->dl_safe_level)) == 0)
      continue;
    if (type != rule->object.rtype)
      continue;
    if (type == RULE_IOCTL && limits != rule->object.limits)
      continue;
    if (type == RULE_FILE && (limits & rule->object.limits) == 0)
      continue;
    if (!strmismatch(path, rule->object.file_path))
      return 1;
  }
  return 0;
}

/**
 * dlpack_file_open - 挂载到open系统调用的钩函数
 * @file: 内核描述一个打开的文件的结构体
 *
 * Return:
 *   0: 成功
 *   -EPERM: 失败
 */
int dlpack_file_open(struct file *file) {
  int ret = 0, flag = 0;
  int accmode = file->f_flags & O_ACCMODE;
  char *path = get_file_path(file);
  __auto_type ctx = get_task_ctx(current);

  if (!ctx)
    return 0;

  process_syscall(ctx, "E_SP_OPEN");

  if (accmode == O_WRONLY)
    flag = 2;
  else if (accmode == O_RDONLY)
    flag = 4;
  else if (accmode == O_RDWR)
    flag = 6;

  if (do_sysp_check(ctx->satisfied, RULE_FILE, path, flag)) {
    dlpack_info("syscall policy check failed for open");
    ret = -EPERM;
    goto out;
  }

  ret = (state_check(path, RULE_FILE, flag) == -1) ? -EPERM : 0;

out:
  if (path)
    free_page(path);
  return ret;
}

/**
 * dlpack_file_ioctl - 挂载到ioctl系统调用的钩函数
 * @file: 内核描述一个打开的文件的结构体
 * @other: 其他参数未使用
 *
 * Return:
 *   0: 成功
 *   -1: 失败
 */
int dlpack_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  char *path;
  int ret = 0;
  struct task_ctx *ctx = get_task_ctx(current);

  if (!ctx)
    return 0;

  if ((cmd & 0xff00) >> 8 != 0x15)
    return 0;

  path = get_file_path(file);
  process_syscall(ctx, "E_SP_IOCTL");

  if (do_sysp_check(ctx->satisfied, RULE_IOCTL, path, cmd)) {
    dlpack_err("syscall policy check failed for ioctl, cmd: %u", cmd);
    ret = -EPERM;
    goto out;
  }

  ret = (state_check(path, RULE_IOCTL, cmd) == -1) ? -EPERM : 0;
  if (ret == -EPERM)
    dlpack_err("scene policy check failed for ioctl, cmd: %u", cmd);

out:
  if (path)
    free_page(path);
  return ret;
}

/**
 * dlpack_mmap_file - 挂载到mmap系统调用的钩函数
 * @file: 内核描述一个打开的文件的结构体
 * @other: 其他参数未使用
 *
 * Return:
 *   0: 成功
 *   -EPERM: 失败
 */
int dlpack_mmap_file(struct file *file, unsigned long reqprot,
                     unsigned long prot, unsigned long flags) {
  char *path;
  int ret = 0, flag = 0;

  process_syscall(get_task_ctx(current), "E_SP_OPEN");

  // judge if need check by syscall_pattern
  if (!should_check()) {
    return 0;
  }

  path = get_file_path(file);

  if ((file->f_flags & O_ACCMODE) == O_RDONLY)
    flag = 4;
  else if ((file->f_flags & O_ACCMODE) == O_WRONLY)
    flag = 2;
  else if ((file->f_flags & O_ACCMODE) == O_RDWR)
    flag = 6;

  if (rules_check(path) == -1) {
    ret = -EPERM;
    goto out;
  }

  if (state_check(path, 1, flag) == -1) {
    ret = -EPERM;
    goto out;
  }

out:
  if (path)
    free_page(path);
  return ret;
}

// test : check securityfs permission
#define DRVING_STATE 0x1
#define WIFI_CONNECT 0x2
#define OWNER_IN_CAR 0x4
// #define BLUETOOTH_CONNECT 0x8

int securityfs_check(void) {
  struct fsm_state *state;

  // get current state
  state = get_global_state();
  dlpack_info("checking securityfs permission, state id is : %d \n", state->id);

  // under driving state or the car owner is not in car, it is not allowed to
  // modify securityfs
  if (state->id & DRVING_STATE || !(state->id & OWNER_IN_CAR)) {
    return -1;
  }

  return 0;
}
