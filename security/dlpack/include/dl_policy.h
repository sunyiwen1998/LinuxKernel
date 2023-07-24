#ifndef _DL_POLICY_H
#define _DL_POLICY_H

#include "dlpack.h"

enum rule_type {
    RULE_CAP = 0,
    RULE_FILE,
    RULE_IOCTL,
};

#define DL_MAX_STATE_NUM 128           // 策略允许下，最多的state定义数量
#define DL_MAX_PERMISSION_NUM 128      // 策略允许下，最多的permission定义数量
#define DL_MAX_RULE_NUM 256            // 策略允许下，每个permission最多的rule数量

// # define DL_MAX_STATE_NUM 128           // 策略允许下，最多的state定义数量
// # define DL_MAX_RULE_NUM 256            // 策略允许下，每个state下允许最多的rule数量

/**
 *  ！！！！ 默认策略传入格式 ！！！！
 *
 *  state（整数） level（整数，代表敏感程度） keyword（整数，0、1、2代表deny、allow、audit） 1（整数，代表“file”） path（字符串） limit（整数）
 *  或
 *  state level keyword 0（代表“cap”） capnum（整数）
 *
 *  例如传入：
 *  256 1 1 1 /path/to/file1 6
 *  代表了当场景为256（10进制表示）的时候，有一条敏感rule生效，rule的内容是：allow file /path/to/file1 rw
 *
 *  传入：
 *  257 0 1 0 10
 *  代表了当场景为257时，有一条非敏感rule生效，rule的内容是：allow cap 10  
 */

// rule中的客体信息定义
struct dl_rule_object {
    enum rule_type rtype;

    char          *file_path;    // 文件路径

    /**
     * 如果客体是file，则limits代表rwx三种权限的组合
     * 如果客体是cap，则limits代表cap的编号
     * 如果客体是ioctl，则limits代表ioctl的cmd
     */
    int            limits;
};

// rule定义，包含 关键词+客体信息+安全等级
struct dl_rule {
    struct list_head      node;
    int                   keyword;
    struct dl_rule_object object;          // 客体信息
    int                   dl_safe_level;   // 安全等级
};

#define for_each_rule(rulep, head) \
    list_for_each_entry(rulep, head, node)

int find_file_rule(struct list_head *,int, char *, int);
int find_ioctl_rule(struct list_head *rule_head, int keyword, char *path,
		    int cmd);
int find_cap_rule(struct list_head *, int, int);
void rules_del(struct list_head *rules);
int strmismatch(const char *a, const char *b);

#endif // _DL_POLICY_H
