#include "include/dl_policy.h"
#include <linux/string.h>

/**
 * @brief Like strcmp, but extended to support checking for asterisks.
 */
int strmismatch(const char *a, const char *b) {
  while (*a || *b) {
    if (*a != *b)
      return *a != '*' && *b != '*';
    if (*a == 0 || *b == 0)
      return 1;
    a++;
    b++;
  }
  return 0;
}

int find_file_rule(struct list_head *rule_head, int keyword, char *path,
                   int limit) {
  struct dl_rule_object o_now;
  struct dl_rule *rule;

  if (list_empty(rule_head) == 1) {
    dlpack_info("no rules in this state !!! ");
  }

  list_for_each_entry(rule, rule_head, node) {
    // dlpack_info("DLPack : to find %d, rule keyword is : %d \n", keyword,
    // rule->keyword);
    if (rule->keyword != keyword)
      continue;
    o_now = rule->object;
    if (o_now.rtype == 1 && !strmismatch(o_now.file_path, path) &&
        ((limit & o_now.limits) == limit)) {
      dlpack_debug(
          "DLPack : found rule !! type = %d, compare = %d, file_limits = %d \n",
          1, !strcmp(o_now.file_path, path), o_now.limits);
      return 0;
    }
  }
  return -1;
}

int find_ioctl_rule(struct list_head *rule_head, int keyword, char *path,
                    int cmd) {
  struct dl_rule_object o_now;
  struct dl_rule *rule;

  if (list_empty(rule_head) == 1) {
    dlpack_info("DLPack : no rules in this state !!! ");
  }
  dlpack_info("Current ioctl path: %s, cmd: %d", path, cmd);

  list_for_each_entry(rule, rule_head, node) {
    // dlpack_info("DLPack : to find %d, rule keyword is : %d \n", keyword,
    // rule->keyword);
    if (rule->keyword != keyword)
      continue;
    o_now = rule->object;
    dlpack_info("Current rule: type: %d, path: %s, limits: %d", o_now.rtype,
                o_now.file_path, o_now.limits);
    if (o_now.rtype == 2 && !strmismatch(o_now.file_path, path) &&
        o_now.limits == cmd) {
      dlpack_info(
          "DLPack : found rule !! type = %d, compare = %d, file_limits = %d \n",
          2, !strcmp(o_now.file_path, path), o_now.limits);
      return 0;
    }
  }
  return -1;
}

int find_cap_rule(struct list_head *rule_head, int keyword, int capnum) {
  struct dl_rule_object o_now;
  struct dl_rule *rule;

  if (list_empty(rule_head) == 1) {
    dlpack_info("DLPack : no rules in this state !!! ");
  }

  list_for_each_entry(rule, rule_head, node) {
    if (rule->keyword != keyword)
      continue;
    o_now = rule->object;
    if (o_now.rtype == 0 && o_now.limits == capnum)
      return 0;
  }
  return -1;
}

/*
 * rtype为关键参数：0-cap，1-file, 2-ioctl
 * file,ioctl 类型客体必需参数 : keyword、path、limit
 * cap类型客体必需参数 : kerword, limit
 ***** 非必须参数可以填写-1 *****
 */
int find_rule(struct list_head *rule_head, int keyword, int rtype, char *path,
              int limit) {
  if (rtype == 1)
    return find_file_rule(rule_head, keyword, path, limit);
  else if (rtype == 0)
    return find_cap_rule(rule_head, keyword, limit);
  else
    return find_ioctl_rule(rule_head, keyword, path, limit);
}

void rules_del(struct list_head *rules) {
  struct dl_rule *this, *tmp;

  list_for_each_entry_safe(this, tmp, rules, node) {
    list_del(&this->node);
    kfree(this);
  }
}
