#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// 配置文件路径信息
#define STATE_PATH  "/etc/azlsm/azconfig"     // 1 or 0
#define ROLES_PATH  "/etc/azlsm/roleconfig"   // test:1
#define ROLES_MAX_NUM_LENGTH 100
#define USERS_PATH  "/etc/azlsm/userconfig"    // user1:role1,role2

//权限信息
#define SYSCALL_MKDIR 1
#define SYSCALL_RMDIR 2
#define SYSCALL_RENAME 4

char Permission_List[8][20] = { "No permission!\0", "MKDIR\0", "RMDIR\0", "MKDIR,RMDIR\0", "RENAME\0", "MKDIR,RENAME\0", "RMDIR,RENAME\0", "MKDIR,RMDIR,RENAME\0"};


// 函数声明
void ShowHelp();            //功能列表 help 信息
void ShowALLInfo();         //显示用户、角色信息
void ShowInfo(int a);       //显示用户信息
int GetState();             //得到AzLSM启用状态
int SetState(int op);      //设置更改AzLSM状态
int AddRole(const char *role, int permission); //增加角色
int DelRole(const char *role);  //删除角色
int ChangeRole(const char *role, int permission); //改变角色
int ExitRole(const char *role); //判断角色是否存在
int ChangeUserRole(int userid,const char *role);// 更改用户角色

// 初始化
void Init(); //初始化生成配置文件
void Init_S();
void Init_U();
void Init_R();



int main(int argc ,char *argv[])
{   
    Init();

    //printf("%d\n",__LINE__);
    //判断是否有参
    if(argc == 1)
    {
        printf ("azm: missing arguments\n");
        printf ("Try \'azm --help\' for more information\n");
        return 0;
    }

    //printf("%d\n",__LINE__);
    // 显示帮助信息
    if(!strcmp (argv[1], "--help"))
    {
        ShowHelp();
        return 0;
    }

    //printf("%d\n",__LINE__);
    // 显示用户、角色信息
    if(!strcmp (argv[1], "-i"))
    {
        if (argc == 2)
        {
            ShowALLInfo ();
            return 0;
        }

        if (!strcmp (argv[2],"users"))
        {
            ShowInfo (2);
            return 0;
        }

        if (!strcmp (argv[2],"roles"))
        {
            ShowInfo (1);
            return 0;
        }

        printf ("Error: unknow argument after -info\n");
        return 0;
    }

    //printf("%d\n",__LINE__);
    // 显示AzLSM模块启用状态
    if (!strcmp (argv[1], "-s"))
    {
        if (argc > 3 )
        {
            printf ("Error: invalid arguments after -state\n") ;
            return 0;
        }

        if (argc == 2)
        {
            int state = GetState ();

            if (state == 1)
            {
                printf ("AzLSM State: Enable\n");
            }
            else if (state == 0)
            {
                printf ("AzLSM State: Disable\n");
            }
            else{
                printf ("Error : State invalid !\n");
            }
            return 0;
        }

        // 设置AzLSM为启动态
        if (!strcmp(argv[2], "enable"))
        {
            //printf("%d\n",__LINE__);
            if (SetState(1) == 1)
                printf ("AzLSM state: Enable!\n");
            return 0;
        }
        // 设置AzLSM为禁用态
        if (!strcmp(argv[2], "disable"))
        {
            //printf("%d\n",__LINE__);
            if (SetState(0) == 1)
			    printf ("AzLSM State: Disable!\n") ;
                return 0;
        }

        printf("Error: invalid argument option\n");
        return 0;
    }

    //printf("%d\n",__LINE__);
    //增加role
    if (!strcmp (argv[1], "-ar"))
    {
        if (argc != 4)
		{
			printf ("Error: invalid arguments after -addrole\n") ;
			return 0 ;
		}

        if (AddRole (argv[2],atoi(argv[3])) == 1)
            printf ("Role added successfully\n") ;
        else
            printf ("Role add failed\n") ;
        
        return 0;
    }

    //printf("%d\n",__LINE__);
    //删除role
    if (!strcmp (argv[1], "-dr"))
    {
        if (argc != 3)
		{
			printf ("Error: invalid arguments after -addrole\n") ;
			return 0 ;
		}

        if (DelRole (argv[2]) == 1)
            printf ("Role deleted successfully\n") ;
        else
            printf ("Role delete failed\n") ;
        
        return 0;
    }

    //printf("%d\n",__LINE__);
    //改变role
    if (!strcmp (argv[1], "-cr"))
    {
        if (argc != 4)
		{
			printf ("Error: invalid arguments after -addrole\n") ;
			return 0 ;
		}

        if (ChangeRole (argv[2],atoi(argv[3])) == 1)
            printf ("Role changed successfully\n") ;
        else
            printf ("Role change failed\n") ;
        
        return 0;
    }
    //printf("%d\n",__LINE__);

    
    if (!strcmp (argv[1], "-cur"))
    {
        if (ChangeUserRole(atoi(argv[2]),argv[3]) == 1)
        {
            printf ("UserRole changed successfully\n") ;
            ShowALLInfo ();
        }
        else{
            printf ("UserRole change failed\n");
        }
    }
    return 0;
}

void Init()
{
    Init_S();
    Init_R();
    Init_U();
    return ;
}

void Init_S()
{
    // 检查stateconfig
    FILE *fpps;
    fpps = fopen(STATE_PATH,"rb");
    if (fpps == NULL)
    {
        FILE *fps ;
        fps = fopen(STATE_PATH,"wb");
        if (fps == NULL)
        {
            printf("Error opening file. %s\n",STATE_PATH);
            return ;
        }
        int st = 0;
        fwrite(&st, sizeof(st), 1, fps);
        fclose(fps);
    }
    else{
    fclose(fpps);
    }
}

void Init_U()
{
    // 检查UserConfig
    FILE *fpp;
    fpp = fopen(USERS_PATH, "rb");
    if (fpp == NULL)
    {
        FILE *fp, *out;
        char line[256];
        const char delim[2] = ":";
        int uid;
        char *token;

        fp = fopen("/etc/passwd", "r");
        if (fp == NULL)
        {
            printf("Error opening file /etc/passwd .\n");
            return ;
        }

        out = fopen(USERS_PATH, "wb"); // 打开输出文件
        if (out == NULL)
        {
            printf("Error opening file. %s\n",USERS_PATH);
            return ;
        }

        while (fgets(line, sizeof(line), fp))
        {
            token = strtok(line, delim); // 获取用户名
            token = strtok(NULL, delim); // 跳过密码
            uid = atoi(strtok(NULL, delim)); // 获取UID并转换为整数
            if (uid >= 1000) // 仅输出UID大于1000的用户
            {
                fwrite(&uid, sizeof(uid) , 1 ,out);
                char defaultname[] = ":_r";
                fwrite(defaultname, sizeof(char), strlen(defaultname), out);
                fwrite("\n", sizeof(char), 1, out);
            }
        }

        fclose(fp);
        fclose(out);
    }
   else{
    fclose(fpp);

   }

}

void Init_R()
{
    
    FILE *fppr;
    char separator =":";
    fppr = fopen(ROLES_PATH, "rb");
    if(fppr == NULL)
    {
        FILE* fp = fopen(ROLES_PATH, "wb");
    // 检查RoleConfig
        if (!fp) {
            printf("Failed to open file.\n");
            return 1;
        }

        int nums[] = { 0,0};
        char* names[] = { "_r" ,"_rr"};
        size_t count = sizeof(nums) / sizeof(int);

        for (size_t i = 0; i < count; i++) {
            // 写入 num
            if (fwrite(&nums[i], sizeof(int), 1, fp) != 1) {
                printf("Failed to write num.\n");
                fclose(fp);
                return 1;
            }

            // 写入分隔符 ":"
            if (fwrite(":", sizeof(char), 1, fp) != 1) {
                printf("Failed to write separator.\n");
                fclose(fp);
                return 1;
                }

            // 写入 name
            if (fwrite(names[i], sizeof(char), strlen(names[i]), fp) != strlen(names[i])) {
                printf("Failed to write name.\n");
                fclose(fp);
                return 1;
                }

            // 写入换行符 "\n"
            if (fwrite("\n", sizeof(char), 1, fp) != 1) {
                printf("Failed to write newline.\n");
                fclose(fp);
                return 1;
                }
        }

        fclose(fp);
       
    }
    else
    {
    fclose(fppr);
    }
}

void ShowHelp()
{
        printf ("This is a security module with simple RBAC security functions, based on LSM.\n");
        printf ("Usage: azm [OPTION] \n");
        printf ("Options:\n");
        printf ("    --help       Display this information.\n");
        printf ("    -i        Display users and roles information\n");
        printf ("    -s        Display AzLSM state\n");
        printf ("    -ar <role name> <permpermission>     Add a role\n");
        printf ("    -cr <role name> <permpermission>  Change a role\n");
        printf ("    -dr <role name>                      Del a role\n");
        printf ("    -cur userid role               Change a UserRole\n");
}

void ShowALLInfo()
{
    ShowInfo(1);
    ShowInfo(2);
}

void ShowInfo(int a)
{
    FILE *fp;
    if (a == 1)
    {
        fp = fopen(ROLES_PATH, "rb");
        printf("Roles informations:\n");
        if (!fp) {
            printf("Failed to open file.\n");
            return ;
        }
    }
    else
    {
        fp = fopen(USERS_PATH, "rb");
        printf("Users informations:\n");
        if (!fp) {
            printf("Failed to open file.\n");
            return ;
        }
    }

    int num;
    char name[256];
    size_t nameLen;
    char separator;
    int result;

    while (!feof(fp)) {
        // 读取 num
        result = fread(&num, sizeof(int), 1, fp);

        if (result != 1) {
            if (feof(fp)) {
                break;  // 到达文件末尾，退出循环
            }

            printf("Failed to read num.\n");
            fclose(fp);
            return 1;
        }

        // 读取分隔符 ":"
        result = fread(&separator, sizeof(char), 1, fp);

        if (result != 1 || separator != ':') {
            printf("Invalid format.\n");
            fclose(fp);
            return 1;
        }

        // 读取 name
        nameLen = 0;
        
        while (1) {
            result = fread(&name[nameLen], sizeof(char), 1, fp);

            if (result != 1) {
                printf("Failed to read name.\n");
                fclose(fp);
                return 1;
            }

            if (name[nameLen] == '\n') {
                name[nameLen] = '\0';  // 将换行符替换为字符串终止符
                break;  // 到达行末，退出循环
            }

            nameLen++;

            if (nameLen >= sizeof(name)) {
                printf("Name too long.\n");
                fclose(fp);
                return 1;
            }
        }

        // 输出 num 和 name
        if( a== 2)
        {
            printf("%d:%s\n", num, name);

        }
        else{
            printf("%s:%d\n", name,num);
        }
    }

    fclose(fp);
}

int GetState()
{
    FILE *fp;
    int st;

    fp = fopen(STATE_PATH, "r");
    if (fp == NULL) {
        printf("Failed to open file. Please check %s\n",STATE_PATH);
        return 0;
    }

    fread(&st, sizeof(st), 1 , fp);
    fclose(fp); 

    return st;
}

int SetState(int op)
{
    if (op == GetState())
    {
        printf ("Status does not need to be changed.\n");
        return 1;
    }

    FILE *fp;

    fp = fopen(STATE_PATH, "w");
    if (fp == NULL) {
        printf("Failed to open file. Please check %s\n",STATE_PATH);
        return 0;
    }

    fwrite(&op, sizeof(op), 1, fp);
    fclose(fp);
    return 1;
}

int ExitRole(const char *role)
{
    FILE* fp = fopen(ROLES_PATH, "rb");

    if (!fp) {
        printf("Failed to open file.\n");
        return 1;
    }

    int num;
    char name[256];
    size_t nameLen;
    char separator;
    int result;

    while (!feof(fp)) {
        // 读取 num
        result = fread(&num, sizeof(int), 1, fp);

        if (result != 1) {
            if (feof(fp)) {
                break;  // 到达文件末尾，退出循环
            }

            printf("Failed to read num.\n");
            fclose(fp);
            return 1;
        }

        // 读取分隔符 ":"
        result = fread(&separator, sizeof(char), 1, fp);

        if (result != 1 || separator != ':') {
            printf("Invalid format.\n");
            fclose(fp);
            return 1;
        }

        // 读取 name
        nameLen = 0;

        while (1) {
            result = fread(&name[nameLen], sizeof(char), 1, fp);

            if (result != 1) {
                printf("Failed to read name.\n");
                fclose(fp);
                return 1;
            }

            if (name[nameLen] == '\n') {
                name[nameLen] = '\0';  // 将换行符替换为字符串终止符
                break;  // 到达行末，退出循环
            }

            nameLen++;

            if (nameLen >= sizeof(name)) {
                printf("Name too long.\n");
                fclose(fp);
                return 1;
            }

        }

        if(!strcmp(role,name))
        {
            fclose(fp);
            return 1;
        }
        // 输出 num 和 name
        //printf("%d:%s\n", num, name);
    }

    fclose(fp);
    return 0;
}

int AddRole(const char *role, int permission)
{
    if (ExitRole (role) == 0)
    {
        char separator =":";
        FILE *fpr ;
        fpr = fopen(ROLES_PATH,"ab");
        if (fpr == NULL)
        {
            printf("Error opening file. %s\n",ROLES_PATH);
            return ;
        }
        fwrite(&permission, sizeof(permission) , 1 ,fpr);
        fwrite(":", sizeof(char), 1, fpr);
        fwrite(role, sizeof(char), strlen(role), fpr);
        fwrite("\n", sizeof(char), 1, fpr);
        fclose(fpr);
        return 1;
    }
    printf("Role already exists in configuration file.\n");
    return 0;
}

int DelRole(const char *role)
{
    if (ExitRole (role) == 1)
    {
        FILE *fp, *output_file;
        char *temp_filename = "/etc/azlsm/roleconfig.tmp";
        output_file = fopen(temp_filename, "wb");
        if (output_file == NULL) 
        {
            printf("Error opening temp_filenmae file. Please check %s\n", temp_filename);
            return 0;
        }
        int num;
        char name[256];
        size_t nameLen;
        char separator;
        int result;
        fp = fopen(ROLES_PATH, "rb");

        if (fp == NULL) 
        {
            printf("Error opening config file.Please check %s\n",ROLES_PATH);
            return 0;
        }

        while (!feof(fp)) {
            // 读取 num
            result = fread(&num, sizeof(int), 1, fp);

            if (result != 1) {
                if (feof(fp)) {
                    break;  // 到达文件末尾，退出循环
                }

                printf("Failed to read num.\n");
                fclose(fp);
                return 1;
            }

            // 读取分隔符 ":"
            result = fread(&separator, sizeof(char), 1, fp);

            if (result != 1 || separator != ':') {
                printf("Invalid format.\n");
                fclose(fp);
                return 1;
            }

            // 读取 name
            nameLen = 0;
            
            while (1) {
                result = fread(&name[nameLen], sizeof(char), 1, fp);

                if (result != 1) {
                    printf("Failed to read name.\n");
                    fclose(fp);
                    return 1;
                }

                if (name[nameLen] == '\n') {
                    name[nameLen] = '\0';  // 将换行符替换为字符串终止符
                    break;  // 到达行末，退出循环
                }

                nameLen++;

                if (nameLen >= sizeof(name)) {
                    printf("Name too long.\n");
                    fclose(fp);
                    return 1;
                }
            }

            if(strcmp(name,role))
            {
                fwrite(&num, sizeof(num) , 1 ,output_file);
                fwrite(":", sizeof(char), 1, output_file);
                fwrite(name, sizeof(char), strlen(name), output_file);
                fwrite("\n", sizeof(char), 1, output_file);
            }
        }

        // 关闭文件
        fclose(fp);
        fclose(output_file);


        // 删除原始配置文件并将临时文件重命名为原始配置文件的名称
        if (remove(ROLES_PATH) != 0) {
            printf("Error deleting input file.\n");
            return 0;
        }
        if (rename(temp_filename, ROLES_PATH) != 0) {
            printf("Error renaming output file.\n");
            return 0;
        }
        return 1;
    }
    printf("Role not exists in configuration file.\n");
    return 0;
}


int ChangeRole(const char *role, int permission)
{
    DelRole(role);
    AddRole(role,permission);
    return 1;
}

int ChangeUserRole(int userid,const char *role) 
{
    FILE *fp, *output_file;
    char *temp_filename = "/etc/azlsm/userconfig.tmp";
    output_file = fopen(temp_filename, "wb");
    if (output_file == NULL) 
    {
        printf("Error opening temp_filenmae file. Please check %s\n", temp_filename);
        return 0;
    }
    int num;
    char name[256];
    size_t nameLen;
    char separator;
    int result;
    fp = fopen(USERS_PATH, "rb");

    if (fp == NULL) 
    {
        printf("Error opening config file.Please check %s\n",ROLES_PATH);
        return 0;
    }

    while (!feof(fp)) {
        // 读取 num
        result = fread(&num, sizeof(int), 1, fp);

        if (result != 1) {
            if (feof(fp)) {
                break;  // 到达文件末尾，退出循环
            }

            printf("Failed to read num.\n");
            fclose(fp);
            return 1;
        }

        // 读取分隔符 ":"
        result = fread(&separator, sizeof(char), 1, fp);

        if (result != 1 || separator != ':') {
            printf("Invalid format.\n");
            fclose(fp);
            return 1;
        }

        // 读取 name
        nameLen = 0;
        
        while (1) {
            result = fread(&name[nameLen], sizeof(char), 1, fp);

            if (result != 1) {
                printf("Failed to read name.\n");
                fclose(fp);
                return 1;
            }

            if (name[nameLen] == '\n') {
                name[nameLen] = '\0';  // 将换行符替换为字符串终止符
                break;  // 到达行末，退出循环
            }

            nameLen++;

            if (nameLen >= sizeof(name)) {
                printf("Name too long.\n");
                fclose(fp);
                return 1;
            }
        }

        if(num != userid)
        {
            fwrite(&num, sizeof(num) , 1 ,output_file);
            fwrite(":", sizeof(char), 1, output_file);
            fwrite(name, sizeof(char), strlen(name), output_file);
            fwrite("\n", sizeof(char), 1, output_file);
        }
        else
        {
            fwrite(&num, sizeof(num) , 1 ,output_file);
            fwrite(":", sizeof(char), 1, output_file);
            fwrite(role, sizeof(char), strlen(role), output_file);
            fwrite("\n", sizeof(char), 1, output_file);
        }
    }

    // 关闭文件
    fclose(fp);
    fclose(output_file);


    // 删除原始配置文件并将临时文件重命名为原始配置文件的名称
    if (remove(USERS_PATH) != 0) {
        printf("Error deleting input file.\n");
        return 0;
    }
    if (rename(temp_filename, USERS_PATH) != 0) {
        printf("Error renaming output file.\n");
        return 0;
    }
    return 1;   

}