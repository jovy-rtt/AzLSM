#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/uaccess.h>


// 配置文件路径信息
#define STATE_PATH  "/etc/azlsm/azconfig"     // 1 or 0
#define ROLES_PATH  "/etc/azlsm/roleconfig"   // test:1
#define ROLES_MAX_NUM_LENGTH 20
#define MAX_ROLENAME_LENTHG 25
#define USERS_PATH  "/etc/azlsm/userconfig"    // uid:role1

//权限信息
#define SYSCALL_MKDIR 1
#define SYSCALL_RMDIR 2
#define SYSCALL_RENAME 4

//是否通过
#define PASS 0
#define NOPASS 1
#define ERR -1
#define Enabl 1
#define Disabl 0

char Permission_List[8][20] = { "No permission!\0", "MKDIR\0", "RMDIR\0", "MKDIR,RMDIR\0", "RENAME\0", "MKDIR,RENAME\0", "RMDIR,RENAME\0", "MKDIR,RMDIR,RENAME\0"};


int az_inode_mkdir(struct inode *dir, struct dentry *dentry,umode_t mode); //hook mkdir
int az_inode_rmdir(struct inode *dir, struct dentry *dentry);       //hook rmdir
int az_inode_rename(struct inode *old_dir, struct dentry *old_dentry,struct inode *new_dir,struct dentry *new_dentry);  //hook rename
int GetEnable(void); // 得到AzLSM启动状态
int GetPerm(int uid); //  得到当前用户角色的权限
int GetUseruid(void); //得到当前用户uid



/* 定义一个新的安全钩子 */
struct security_hook_list AzLSM_hook[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(inode_mkdir, az_inode_mkdir),
    LSM_HOOK_INIT(inode_rmdir, az_inode_rmdir),
	LSM_HOOK_INIT(inode_rename, az_inode_rename),
};


void __init AzLSM_add_hooks(void)
{
    // 打印相关信息，通过dmesg查看 建议：dmesg | grep AzLSM
    pr_info("[AzLSM-info] : This is a security module with simple RBAC security functions, based on LSM \n");
    /* 注册Az的安全钩子 */
    security_add_hooks(AzLSM_hook, ARRAY_SIZE(AzLSM_hook), "AzLSM");   //添加安全模块函数
}

static __init int AzLSM_init(void)
{
    AzLSM_add_hooks();
    return 0;
}

int az_inode_mkdir(struct inode *dir, struct dentry *dentry,umode_t mode)
{
    int user_uid;
    int user_perm ;
    user_uid =  GetUseruid();
    //pr_info("[AzLSM-test] : mkdir op ! uid = %d \n ", user_uid);
    if (GetEnable() == Disabl)
        return PASS ;
    
    pr_info("[AzLSM] : State is enable!\n");

    user_perm = GetPerm(user_uid);

    if (user_perm == EINVAL || user_perm == ERR)
    {
        pr_info("[AzLSM-test] GetPerm failed!  return PASS \n");
        return PASS;
    }
    pr_info("[AzLSM] Current user permission : %s \n",Permission_List[user_perm]);
    //PrintPerm(user_perm);

    if ( (user_perm & SYSCALL_MKDIR ) != 0)
    {
        pr_info("[AzLSM] MKDIR PASS!\n");
        return PASS;
    }

    pr_info("[AzLSM] MKDIR NO PASS!\n");
    // return PASS ;
    return NOPASS;
}

int az_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int user_uid;
    int user_perm ;
    // 判断是否启用，未启用不更改
    if (GetEnable() == Disabl)
        return PASS ;
    
    pr_info("[AzLSM] : State is enable!\n");
    
    user_uid =  GetUseruid();

    user_perm = GetPerm(user_uid);

    if (user_perm == EINVAL || user_perm == ERR)
    {
        pr_info("[AzLSM-test] GetPerm failed! return PASS \n");
        return PASS;
    }

    pr_info("[AzLSM] Current user permission : %s \n",Permission_List[user_perm]);
    //PrintPerm(user_perm);

    if ( (user_perm & SYSCALL_RMDIR) != 0)
    {
        pr_info("[AzLSM] RMDIR PASS!\n");
        return PASS;
    }

    pr_info("[AzLSM] RMDIR NO PASS! \n");
    // return PASS ;
    
    return NOPASS;
}

int az_inode_rename(struct inode *old_dir, struct dentry *old_dentry,struct inode *new_dir,struct dentry *new_dentry)
{
    int user_uid;
    int user_perm ;

    // 判断是否启用，未启用不更改
    if (GetEnable() == Disabl)
        return PASS ;

    pr_info("[AzLSM] : State is enable!\n");

    user_uid =  GetUseruid();
    user_perm = GetPerm(user_uid);
    if (user_perm == EINVAL || user_perm == ERR)
    {
        pr_info("[AzLSM-test] GetPerm failed!  return PASS \n");
        return PASS;
    }

    pr_info("[AzLSM] Current user permission : %s \n",Permission_List[user_perm]);
    //PrintPerm(user_perm);

    if ( (user_perm & SYSCALL_RENAME) != 0)
    {
        pr_info("[AzLSM] RENAME PASS!\n");
        return PASS;
    }

    pr_info("[AzLSM] RENAME NO PASS!\n");
    // return PASS ;
    return NOPASS;

}

int GetEnable(void)
{
    int user_uid;
    user_uid =  GetUseruid();

    if (user_uid < 1000)
    {
        return Disabl;
    }

    struct file *fout = filp_open (STATE_PATH, O_RDONLY, 0) ;
	char state_buf[sizeof(int)] ;
	int state ;
	mm_segment_t fs ;


    //pr_info("[AzLSM-test] : GetEnable uid = %d , line = 177 \n",user_uid);


	if (!fout || IS_ERR(fout))
	{
		pr_info ("[AzLSM] : [GetState] load file error. please check %s\n ",STATE_PATH) ;
		return Disabl ;
	}
	
	fs = get_fs () ;
	set_fs (KERNEL_DS) ;
	
	vfs_read(fout, state_buf, sizeof(int), &fout->f_pos) ;
	memcpy (&state, state_buf, sizeof(int)) ;
	
	set_fs (fs) ;
	filp_close (fout, NULL) ;

    if(state < 0)
    {
        pr_info("[AzLSM] GetState: State error !! State = %d\n" ,state) ;
    }
    
    pr_info("[AzLSM] GetState : %d  uid : %d\n",state, user_uid);

    if (state == 1)
    {
        //pr_info("[AzLSM-test] GetEnable return enable !! \n");
        return Enabl;
    }

    return Disabl ;
}

int GetUseruid(void)
{
    kuid_t uid = current_uid();
    return uid.val;
}


int GetPerm(int uid)
{
    if (uid < 1000) 
    {
        return 7 ;
    }


    // pr_info("[AzLSM-test] : GetPerm uid =, line = 228 \n");
    // return 7;

    struct file *up = filp_open (USERS_PATH, O_RDONLY, 0);
    mm_segment_t fs ;
    char separator ;
    //char role[MAX_ROLENAME_LENTHG+1];
    char name[256];
    int flag = 0;
    int nameLen;
    int _uid ;
    char uid_buf[sizeof(int)] ;
    // perm
    
    int res ;

    if (!up || IS_ERR(up))
    {
        pr_info ("[AzLSM] : GetPerm error .please check %s.\n",USERS_PATH);
        return ERR;
    }

    fs = get_fs () ;
    set_fs (KERNEL_DS) ;

    while ((vfs_read(up ,uid_buf, sizeof(int), &up->f_pos)) > 0 )
    {
        memcpy (&_uid, uid_buf ,sizeof(int));
        res = vfs_read (up ,&separator ,sizeof(char), &up->f_pos);

        if( res < 0 || separator!= ':')
        {
            pr_info("[AzLSM] GetPerm : separatoe is error!\n");
            set_fs (fs) ;
            filp_close (up, NULL) ;
            return ERR;
        }

        nameLen = 0;
        while(1)
        {
            res = vfs_read (up ,&name[nameLen] ,sizeof(char), &up->f_pos);
            if (res < 0 )
            {
                pr_info("[AzLSM] GetPerm : name is error!\n");
                set_fs (fs) ;
                filp_close (up, NULL) ;
                return ERR;
            }

            if (name[nameLen] == '\n') {
                name[nameLen] = '\0';  // 将换行符替换为字符串终止符
                break;  // 到达行末，退出循环
            }

            nameLen ++;

            if (nameLen >= sizeof(name)) {
                pr_info("[AzLSM] GetPerm : Name too long.\n");
                set_fs (fs) ;
                filp_close (up, NULL) ;
                return ERR;
            }

        }

        if (uid == _uid)
        {
            pr_info ("[AzLSM] GetPerm uid: %d , role : %s \n", uid ,name) ;
            flag = 1;
            break ;
        }
    }

    if (flag == 0)
    {
        pr_info ("[AzLSM] GetPerm : cannot found uid : %d!\n" ,uid) ;

        set_fs (fs) ;
        filp_close (up, NULL) ;
        return ERR;
    }

    set_fs (fs) ;
    filp_close (up, NULL) ;

    //perm
    struct file *rp = filp_open (ROLES_PATH, O_RDONLY, 0);
    char newname[256];
    int perm;
    flag = 0;

    if (!rp || IS_ERR(rp))
    {
        pr_info ("[AzLSM] : GetPerm error .please check %s.\n",ROLES_PATH);
        return ERR;
    }

    fs = get_fs () ;
    set_fs (KERNEL_DS) ;

    while ((vfs_read(rp ,uid_buf, sizeof(int), &rp->f_pos)) > 0 )
    {
        memcpy (&perm, uid_buf ,sizeof(int));
        res = vfs_read (rp ,&separator ,sizeof(char), &rp->f_pos);

        if( res < 0 || separator!= ':')
        {
            pr_info("[AzLSM] GetPerm - 2 : separatoe is error!\n");
            set_fs (fs) ;
            filp_close (rp, NULL) ;
            return ERR;
        }

        nameLen = 0;
        while(1)
        {
            res = vfs_read (rp ,&newname[nameLen] ,sizeof(char), &rp->f_pos);
            if (res < 0 )
            {
                pr_info("[AzLSM] GetPerm -2  : name is error!\n");
                set_fs (fs) ;
                filp_close (rp, NULL) ;
                return ERR;
            }

            if (newname[nameLen] == '\n') {
                newname[nameLen] = '\0';  // 将换行符替换为字符串终止符
                break;  // 到达行末，退出循环
            }

            nameLen ++;

            if (nameLen >= sizeof(newname)) {
                pr_info("[AzLSM] GetPerm -2 : Name too long.\n");
                set_fs (fs) ;
                filp_close (rp, NULL) ;
                return ERR;
            }

        }

        if(!strcmp(name,newname))
        {
            //pr_info("[AzLSM] GetPerm find role Perm = %d \n",perm);
            flag = 1;
            break;
        }
    }

    if (flag == 0)
    {
        pr_info ("[AzLSM] GetPerm -2 : cannot found  %d de role !\n" ,uid) ;
        set_fs (fs) ;
        filp_close (rp, NULL) ;
        return ERR;
    }

    set_fs (fs) ;
    filp_close (rp, NULL) ;
    pr_info("[AzLSM-test] : GetPerm uid = %d rolename = %s Perm = %d \n", uid, name , perm);
    return perm;

    //return 7;
}

security_initcall(AzLSM_init);
