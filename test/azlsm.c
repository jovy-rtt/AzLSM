#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>

//是否通过
#define PASS 0
#define NOPASS EINVAL


int az_inode_mkdir(struct inode *dir, struct dentry *dentry,umode_t mode); //hook mkdir
int az_inode_rmdir(struct inode *dir, struct dentry *dentry);       //hook rmdir
int az_inode_rename(struct inode *old_dir, struct dentry *old_dentry,struct inode *new_dir,struct dentry *new_dentry);  //hook rename



/* 定义一个新的安全钩子 */
struct security_hook_list AzLSM_hook[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_mkdir, az_inode_mkdir),
    LSM_HOOK_INIT(inode_rmdir, az_inode_rmdir),
	LSM_HOOK_INIT(inode_rename, az_inode_rename),
};


void __init AzLSM_init(void)
{
    // 打印相关信息，通过dmesg查看 建议：dmesg | grep AzLSM
    pr_info("[AzLSM-info] : This is a security module with simple RBAC security functions, based on LSM \n");
    /* 注册Az的安全钩子 */
    security_add_hooks(AzLSM_hook, ARRAY_SIZE(AzLSM_hook), "AzLSM");   //添加安全模块函数
}

int az_inode_mkdir(struct inode *dir, struct dentry *dentry,umode_t mode)
{
    pr_info("[AzLSM] inode mkdir\n");
    return PASS;
}

int az_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    pr_info("[AzLSM] inode rmdir\n");
    return PASS;
}

int az_inode_rename(struct inode *old_dir, struct dentry *old_dentry,struct inode *new_dir,struct dentry *new_dentry)
{
    pr_info("[AzLSM] inode rename\n");
    return PASS;
}

security_initcall(AzLSM_init);
