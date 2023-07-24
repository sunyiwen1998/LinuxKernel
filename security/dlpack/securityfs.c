// SPDX-License-Identifier: GPL-2.0-only

#include "include/dl_policy.h"
#include "include/dlpack.h"
#include "include/event.h"
#include "include/pattern.h"
#include "include/right_abs.h"
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/string_helpers.h>
#include <linux/sysctl.h>

int sp_cnt = 1;

struct dl_rule *dlpack_unpack_rule(char *temp) {
  int rtype = 0, cap_num = 0, temp_level = 0, temp_keyword = 0, temp_limit;

  struct dl_rule *rule_now;

  rule_now = kmalloc(sizeof(*rule_now), GFP_KERNEL);
  if (rule_now == NULL)
    return NULL;

  char *token, *cur = temp,
               *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  strcpy(delim, " ");
  token = strsep(&cur, delim);
  kstrtoint(token, 10, &temp_level);
  token = strsep(&cur, delim);
  kstrtoint(token, 10, &temp_keyword);
  token = strsep(&cur, delim);
  kstrtoint(token, 10, &rtype);
  pr_info(
      "------------one rule is %s, level is %d, kerword is %d, rtype is %d\n",
      cur, temp_level, temp_keyword, rtype);
  token = strsep(&cur, delim);
  rule_now->keyword = temp_keyword;
  rule_now->dl_safe_level = temp_level;
  if (rtype == 0) {
    kstrtoint(token, 10, &cap_num);
    rule_now->object.rtype = rtype;
    rule_now->object.limits = cap_num;
    pr_info("add new rules,rtype = cap,cap_num=%d\n", cap_num);
  } else if (rtype == 1) {
    rule_now->object.rtype = rtype;
    rule_now->object.file_path = kzalloc(sizeof(char) * 256, GFP_KERNEL);
    strcpy(rule_now->object.file_path, token);
    token = strsep(&cur, delim);
    kstrtoint(token, 10, &temp_limit);
    rule_now->object.limits = temp_limit;
    pr_info("add new rules,rtype = file,file_path=%s\n",
            rule_now->object.file_path);
  } else {
    rule_now->object.rtype = rtype;
    rule_now->object.file_path = kzalloc(sizeof(char) * 256, GFP_KERNEL);
    strcpy(rule_now->object.file_path, token);
    token = strsep(&cur, delim);
    kstrtoint(token, 10, &temp_limit);
    rule_now->object.limits = temp_limit;
    pr_info("add new rules,rtype = ioctl,file_path=%s\n",
            rule_now->object.file_path);
  }
  return rule_now;
}

/**
 * dlpack_write - event文件的write处理函数
 *
 * Return:
 *   >0: 成功写入的字节数
 *   <0: 写入失败
 */
static ssize_t dlpack_write(struct file *filep, const char __user *ubuf,
                            size_t n, loff_t *l) {
  int err, event;
  char *buf, *p, *end;

  buf = memdup_user_nul(ubuf, n);
  p = buf;

  if (n < 4) {
    dlpack_info("Invalid input arguments.");
    n = -EINVAL;
    goto out_free_buf;
  }

  if (strncmp(buf, "$T ", 3) == 0) {
    p += 3;

    while ((char)(*p) == ' ') {
      p++;
    }

    end = strchr(p, '\n');
    if (!end) {
      err = -EINVAL;
      goto out_free_buf;
    }
    *end = '\0';

    event = get_event_id(p);
    if (event >= 0) {
      dlpack_info("trigger event %s: %d", p, event);
      fsm_run(dlpack_fsm, event);
    } else {
      dlpack_info("Unknown event.");
    }
  } else if (strncmp(buf, "$E ", 3) == 0) {
    p += 3;

    while ((char)(*p) == ' ') {
      p++;
    }

    end = strchr(p, '\n');
    if (!end) {
      err = -EINVAL;
      goto out_free_buf;
    }
    *end = '\0';

    add_event(p);
    dlpack_info("add event %s: %d", p, event);
  } else if (strncmp(buf, "$R ", 3) == 0) {
    reset_states();
  } else {
    dlpack_info("DLPack : something happened and trigger not added");
  }

out_free_buf:
  kfree(buf);
  return n;
}

const struct file_operations dlpack_fops = {
    .write = dlpack_write,
};

/**
 * dlpack_syscall_file_write - syscall pattern文件的write处理函数
 *
 * Return:
 *   >0: 成功写入的字节数
 *   <0: 写入失败
 */
static ssize_t dlpack_syscall_file_write(struct file *filep,
                                         const char __user *ubuf, size_t n,
                                         loff_t *l) {
  char *buf, *p, *end;
  char *syscall_name;
  char event[MAX_EVENT_LEN];
  int err, cnt, state_id, evt_id, sp_id;
  struct fsm_state *state1, *state2;
  struct fsm_trans_list *target_trans_item;
  struct dl_rule *rule;

  // test : check securityfs permission
  // int ret;
  // ret = securityfs_check();
  // if(ret < 0) {
  // 	dlpack_info("Modify securityfs interface not allowed under this
  // state."); 	goto out_free_dlp;
  // }

  cnt = 0;
  state1 = get_trie_node(0);

  buf = memdup_user_nul(ubuf, n);
  if (IS_ERR(buf)) {
    err = PTR_ERR(buf);
    goto out_free_dlp;
  }
  p = buf;
  end = strchr(p, '\n');
  if (!end) {
    err = -EINVAL;
    goto out_free_buf;
  }
  *end = '\0';

  if (sp_cnt++ >= 1000) {
    dlpack_info("Too many syscall patterns.");
    err = -EINVAL;
    goto out_free_buf;
  }

  if (n < 4) {
    dlpack_info("Invalid input arguments.");
    err = -EINVAL;
    goto out_free_buf;
  }

  if (strncmp(buf, "$P ", 3) != 0) {
    dlpack_info("Invalid input syntax.");
    err = -EINVAL;
    goto out_free_buf;
  }

  p += 3;

  // 获取每个系统调用
  while (p != NULL) {
    syscall_name = strsep(&p, " ");
    if (strlen(syscall_name) == 0) // 输入了超过一个空格
      continue;
    else if (strlen(syscall_name) == 1)
      break;

    string_upper(syscall_name, syscall_name);
    snprintf(event, MAX_EVENT_LEN, "E_SP_%s", syscall_name);
    if (get_event_id(event) == -EINVAL)
      add_event(event);
    evt_id = get_event_id(event);

    target_trans_item = find_trans_item(state1, evt_id);
    if (!target_trans_item) {
      state_id = (sp_cnt << 6) + cnt++;
      add_trie_node(state_id, sp_cnt);
      state2 = get_trie_node(state_id);
      add_trans(state1, state2, evt_id);
      state1 = state2;
      sp_id = state1->syscall_pattern_id;
    } else {
      state1 = target_trans_item->next_state;
      sp_id = state1->syscall_pattern_id;
      dlpack_info("Trans already added, to %d, trigger syscall %s", state1->id,
                  syscall_name);
    }
  }

  rule = dlpack_unpack_rule(p);
  rule->dl_safe_level = sp_id;
  list_add_tail(&rule->node, &sysp_rules);
  syscall_pattern_version++;

  dlpack_info("Add syscall pattern success.");

out_free_buf:
  kfree(buf);
out_free_dlp:
  return n;
}

const struct file_operations dlpack_syscall_file_fops = {
    .write = dlpack_syscall_file_write,
};

static DEFINE_MUTEX(dlpack_handler_lock);

/*
【目标】通过伪文件系统实现在用户态改变内核态的state-rule对应关系
【规则】
️ 1.改变state-rule对应关系字符串模板：
       changesr [state] [add/delete/change] [rule1's object type] [rule1's cap
num] [rule1' file path] [rule2's object type] [rule2's cap num] [rule2's file
path] ... ️ 2.举例： “changesr 111 add 0 0 1 /driver/cars” ️ 3.有三种事件： ·
add：某一种状态增加若干条rule · delete：某一种状态减少若干条rules ·
change：删除某种状态原来原来拥有的所有rules，然后新增用户设置的state-rules对应
【内核相关代码】
️ 1.伪文件路径: /sys/kernel/security/dlpack/changeRules （需要重新编译+替换内核）
️ 2.内核函数位置： /DLPACK/securityfs.c->dlpack_write2
*/
// #define AAFS_NAME		"dlpackfs"
// static struct vfsmount *dlpackfs_mnt;
// static int dlpackfs_count;

/*

dlpack_read_ops

*/
static ssize_t dlpack_read_changeRules(struct file *filp, char __user *buf,
                                       size_t count, loff_t *ppos) {
  char *temp = (char *)kzalloc(sizeof(char) * 400, GFP_KERNEL);
  ssize_t rc;
  if (*ppos != 0)
    return 0;
  strcat(temp, "You are reading changeRules");
  strcat(temp, "\n");

  rc = simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));
  return rc;
}

// return 0 if add; return 1 if delete; return 2 if change; return -1 if error;
int select_op(char *temp, char **ret_pos, char **ret_cur) {
  char *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  strcpy(delim, " ");
  char *pos, *cur = temp;
  char *token;
  pr_info("The string is %s", cur);
  token = strsep(&cur, delim);
  pos = strsep(&cur, delim);
  token = strsep(&cur, delim);
  pr_info("The action is %s", token);
  pr_info("The state is %s", pos);
  *ret_pos = pos;
  *ret_cur = cur;
  if (strcmp(token, "add") == 0)
    return 0;
  else if (strcmp(token, "delete") == 0)
    return 1;
  else if (strcmp(token, "change") == 0)
    return 2;
  return -1;
}

// changesr 111 add 0 /proc/sys 1 /driver/cars  ，格式：changesr + state_id +
// add  [rtype  cap_num/file_path file_limit] add：某一种状态增加若干条rule
int dlpack_add_Rules(char *temp, int pos) {
  int i = 0;
  int rtype = 0, cap_num = 0, temp_level = 0, temp_keyword = 0, temp_limit;
  struct dl_rule *rule_now;
  struct fsm_state *state_now;
  rule_now = kmalloc(sizeof(*rule_now), GFP_KERNEL);
  if (rule_now == NULL)
    return -ENOMEM;
  state_now = get_state(pos);
  pr_info("finish get state\n");
  if (state_now == NULL) {
    add_state(pos);
    state_now = get_state(pos);
  }
  char *token, *cur = temp,
               *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  strcpy(delim, " ");
  while (cur != NULL) {
    token = strsep(&cur, delim);
    kstrtoint(token, 10, &temp_level);
    token = strsep(&cur, delim);
    kstrtoint(token, 10, &temp_keyword);
    token = strsep(&cur, delim);
    kstrtoint(token, 10, &rtype);
    token = strsep(&cur, delim);
    rule_now->keyword = temp_keyword;
    rule_now->dl_safe_level = temp_level;
    if (rtype == 0) {
      kstrtoint(token, 10, &cap_num);
      pr_info("for state %d,add new rules,rtype=%d,cap_num=%d\n", pos, rtype,
              cap_num);
      rule_now->object.rtype = rtype;
      rule_now->object.limits = cap_num;
    } else {
      pr_info("for state %d,add new rules,rtype=%d,file_path=%s\n", pos, rtype,
              token);
      rule_now->object.rtype = rtype;
      rule_now->object.file_path = kzalloc(sizeof(char) * 256, GFP_KERNEL);
      strcpy(rule_now->object.file_path, token);
      token = strsep(&cur, delim);
      kstrtoint(token, 10, &temp_limit);
      rule_now->object.limits = temp_limit;
    }

    list_add_tail(&rule_now->node, &state_now->rule_head);
  }
  return 0;
}

// changesr 1 delete  取消状态 1 对应的所有rule，但是不删除state本身
int dlpack_delete_Rules(char *temp, int pos) {
  int i = 0;
  int rule_num;
  pr_info("for state %d, delete its rules", pos);
  struct fsm_state *state_now = get_state(pos);
  if (state_now == NULL) {
    return 0;
  }
  char *token, *cur = temp,
               *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  strcpy(delim, " ");
  if (&(state_now->rule_head) != NULL) {
    rules_del(&(state_now->rule_head));
  }

  return 0;
}

// changesr 1 change  5 6 8 9 改变状态 1 对应的rules，将其改为状态1对应第5 6 8
// 9条rules
int dlpack_change_Rules(char *temp, int pos) {
  int i = 0;
  int rtype, rule_num;
  struct fsm_state *state_now = get_state(pos);
  if (state_now == NULL) {
    pr_info("state is NULL\n");
    return 0;
  }
  char *token, *cur = temp,
               *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  struct list_head *node_edit_now = &(state_now->rule_head);
  struct dl_rule *rule_temp = kzalloc(sizeof(struct dl_rule), GFP_KERNEL);
  struct list_head *rule_temp_head;
  rule_temp_head = &(rule_temp->node);
  rule_temp->node.next = kzalloc(sizeof(struct dl_rule), GFP_KERNEL);
  strcpy(delim, " ");
  while (cur != NULL) {
    token = strsep(&cur, delim);
    kstrtoint(token, 10, &rule_num);
    pr_info("for state %d, reserve its rule %d", pos, rule_num);
    while (node_edit_now->next != NULL) {
      if (i == rule_num) {
        rule_temp->node.next = node_edit_now;
        rule_temp = (struct dl_rule *)rule_temp->node.next;
        node_edit_now = node_edit_now->next;
        i++;
        break;
      } else {
        node_edit_now = node_edit_now->next;
      }
      i++;
    }
  }
  state_now->rule_head = *(rule_temp_head->next);
  // list_add_tail(rule_temp_head, &state_now->rule_head);

  return 0;
}

/*
【目标】通过伪文件系统实现在用户态改变内核态的state-rule对应关系
【规则】
️ 1.改变state-rule对应关系字符串模板：
       changesr [state] [add] [rule1's object type] [rule1's cap num/file path]
[rule2's object type] [rule2's cap num/file path] ... changesr [state] [delete]
       changesr [state] [change] [rule_id1,rule_id2,...]
//只保留第id1,id2,...条rule

️ 3.有三种事件：
· add：某一种状态增加若干条rule
· delete：删除某一种状态的所有rules，但是不删除state本身
· change：删除某种状态原来原来拥有的所有rules，然后新增用户设置的state-rules对应
【内核相关代码】
️ 1.伪文件路径: /sys/kernel/security/dlpack/changeRules
️ 2.内核函数位置： /DLPACK/securityfs.c->dlpack_write_changeRules
*/
static ssize_t dlpack_write_changeRules(struct file *file,
                                        const char __user *buf, size_t count,
                                        loff_t *ppos) {
  char temp[400];
  char *cur;
  char *pos;

  int op, ret = 0, state_pos = 0;
  char *str = (char *)kzalloc(sizeof(char) * 400, GFP_KERNEL);

  if (count >= sizeof(temp) || count == 0)
    return -EINVAL;

  if (copy_from_user(temp, buf, count) != 0)
    return -EFAULT;

  temp[count] = '\0';
  if (sscanf(temp, "%s", str) != 1)
    return -EINVAL;

  /*
   * Don't do anything if the value hasn't actually changed.
   * If it is changing reset the level on entries that were
   * set up to be mapped when they were created.
   */
  pr_info("--------------Call dlpack_write_changeRules-------------\n");

  if (strcmp(temp, "clean") == 0) {
    // free the old policy
    reset_states();
    return count;
  }

  op = select_op(temp, &pos, &cur);
  ret = kstrtoint(pos, 10, &state_pos);
  if (op == 0) {

    dlpack_add_Rules(cur, state_pos);

  }

  else if (op == 1) {
    dlpack_delete_Rules(cur, state_pos);
  } else {
    dlpack_change_Rules(cur, state_pos);
  }

  return count;
}
static const struct file_operations dlpack_changeRules_ops = {
    .read = dlpack_read_changeRules,
    .write = dlpack_write_changeRules,
    .llseek = default_llseek,
};

static ssize_t dlpack_read_loadRules(struct file *filp, char __user *buf,
                                     size_t count, loff_t *ppos) {
  char temp[100];
  ssize_t rc;

  if (*ppos != 0)
    return 0;
  strcat(temp, "You are reading loadRules");
  strcat(temp, "\n");
  print_all_state();
  rc = simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));
  return rc;
}

static ssize_t dlpack_write_loadRules(struct file *file, const char __user *buf,
                                      size_t count, loff_t *ppos) {
  char temp[400];

  char *str = (char *)kzalloc(sizeof(char) * 400, GFP_KERNEL);

  if (count >= sizeof(temp) || count == 0)
    return -EINVAL;

  if (copy_from_user(temp, buf, count) != 0)
    return -EFAULT;

  temp[count] = '\0';
  if (sscanf(temp, "%s", str) != 1)
    return -EINVAL;

  /*
   * Don't do anything if the value hasn't actually changed.
   * If it is changing reset the level on entries that were
   * set up to be mapped when they were created.
   */
  pr_info("Call dlpack_write_loadRules\n");

  char *token, *multoken, *cur, *curr;
  char *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  char *delim2 = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  struct fsm_state *state_now;
  struct dl_rule *rule_now;
  int pos;

  strcpy(delim, " ");

  cur = temp;
  // if (temp != NULL)
  // 	pr_info("dlpack_temp: %s\n", temp);

  token = strsep(&cur, delim);
  kstrtoint(token, 10, &pos);
  state_now = get_state(pos);
  if (state_now == NULL) {
    add_state(pos);
    // dlpack_info("Create a new node for pos %d\n", pos);
    state_now = get_state(pos);
  }

  // 先找到对应的rule

  rule_now = dlpack_unpack_rule(cur);
  if (rule_now == NULL) {
    return -ENOMEM;
  }
  list_add_tail(&rule_now->node, &state_now->rule_head);

  return count;
}

static const struct file_operations dlpack_loadRules_ops = {
    .read = dlpack_read_loadRules,
    .write = dlpack_write_loadRules,
    .llseek = default_llseek,
};

// 对这个伪文件进行写入，可以让一个进程拥有指定的rule
static ssize_t dlpack_write_proc_per(struct file *file, const char __user *buf,
                                     size_t count, loff_t *ppos) {
  char temp[400];

  char *str = (char *)kzalloc(sizeof(char) * 400, GFP_KERNEL);

  if (count >= sizeof(temp) || count == 0)
    return -EINVAL;

  if (copy_from_user(temp, buf, count) != 0)
    return -EFAULT;

  temp[count] = '\0';
  if (sscanf(temp, "%s", str) != 1)
    return -EINVAL;

  /*
   * Don't do anything if the value hasn't actually changed.
   * If it is changing reset the level on entries that were
   * set up to be mapped when they were created.
   */
  char *token, *multoken, *cur, *curr;
  char *delim = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  char *delim2 = (char *)kzalloc(sizeof(char) * 4, GFP_KERNEL);
  struct dl_rule *rule_now;

  struct task_ctx *ctx;
  int pos;

  pr_info("Call dlpack_write_proc_per\n");

  ctx = get_task_ctx(current);

  rules_del(&ctx->pr->rules);

  strcpy(delim, " ");
  strcpy(delim2, "\n");

  curr = temp;
  int pid;
  kstrtoint(strsep(&curr, delim2), 10, &pid);
  while (curr != NULL) {
    multoken = strsep(&curr, delim2);
    if (multoken == NULL) {
      break;
    }
    pr_info("add rule --%s-- for process: %d\n", multoken, current->pid);

    cur = multoken;
    rule_now = dlpack_unpack_rule(cur);
    if (rule_now == NULL) {
      return -ENOMEM;
    }
    list_add_tail(&rule_now->node, &ctx->pr->rules);
  }
  return count;
}

static const struct file_operations dlpack_proc_per_ops = {
    .write = dlpack_write_proc_per,
};

static ssize_t dlpack_read_s2rtrace(struct file *filp, char __user *buf,
                                       size_t count, loff_t *ppos) {
  printk(KERN_INFO "[S2RTRACE] dlpack_read_s2rtrace\n");
  char *temp = (char *)kzalloc(sizeof(char) * 400, GFP_KERNEL);
  ssize_t rc;
  if (*ppos != 0)
    return 0;
  strcat(temp, "You are reading changeRules");
  strcat(temp, "\n");
  printk(KERN_INFO "[S2RTRACE] %s\n",temp);
  rc = simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));
  return rc;
}

static ssize_t dlpack_write_s2rtrace(struct file *filep,
                                         const char __user *ubuf, size_t n,
                                         loff_t *l) {
  printk(KERN_INFO "[S2RTRACE] dlpack_write_s2rtrace\n");
  char *buf;
  int err;

  buf = memdup_user_nul(ubuf, n);
  if (IS_ERR(buf)) {
    err = PTR_ERR(buf);
    goto out_free_dlp;
  }
  printk(KERN_INFO "[S2RTRACE] %s\n",buf);
out_free_buf:
  kfree(buf);
out_free_dlp:
  return n;
}

static const struct file_operations dlpack_s2rtrace_ops = {
    .read = dlpack_read_s2rtrace,
    .write = dlpack_write_s2rtrace,
    .llseek = default_llseek,
};

/**
 * dlpack_init_securityfs - securityfs 初始化函数
 *
 * Return:
 *   0: 初始化成功
 *   Others: 初始化失败
 */
static int __init dlpack_init_securityfs(void) {
  int r;
  struct dentry *dir, *file, *syscall_file, *dlpack_loadRules,
      *dlpack_changeRules, *proc_per, *s2rtrace;

  dir = securityfs_create_dir("dlpack", NULL);
  if (IS_ERR(dir)) {
    r = PTR_ERR(dir);
    goto error;
  }

  file = securityfs_create_file("event", 0600, dir, NULL, &dlpack_fops);
  if (IS_ERR(file)) {
    r = PTR_ERR(file);
    goto error;
  }

  syscall_file = securityfs_create_file("syscall_file", 0600, dir, NULL,
                                        &dlpack_syscall_file_fops);
  if (IS_ERR(syscall_file)) {
    r = PTR_ERR(syscall_file);
    goto error;
  }

  dlpack_loadRules = securityfs_create_file("loadRules", 0600, dir, NULL,
                                            &dlpack_loadRules_ops);
  if (IS_ERR(dlpack_loadRules)) {
    r = PTR_ERR(dlpack_loadRules);
    goto error;
  }

  dlpack_loadRules = securityfs_create_file("changeRules", 0600, dir, NULL,
                                            &dlpack_changeRules_ops);
  if (IS_ERR(dlpack_changeRules)) {
    r = PTR_ERR(dlpack_changeRules);
    goto error;
  }

  proc_per =
      securityfs_create_file("proc_per", 0600, dir, NULL, &dlpack_proc_per_ops);
  if (IS_ERR(proc_per)) {
    r = PTR_ERR(proc_per);
    goto error;
  }

  s2rtrace =
        securityfs_create_file("s2rtrace", 0600, dir, NULL, &dlpack_s2rtrace_ops);
  if (IS_ERR(s2rtrace)) {
    r = PTR_ERR(s2rtrace);
    goto error;
  }

  return 0;

error:
  securityfs_remove(file);
  securityfs_remove(syscall_file);
  securityfs_remove(dlpack_loadRules);
  securityfs_remove(dlpack_changeRules);
  securityfs_remove(proc_per);
  securityfs_remove(dir);
  securityfs_remove(s2rtrace);
  return r;
}

fs_initcall(dlpack_init_securityfs);
