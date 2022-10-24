#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<mysql/mysql.h>

#define SUCCESS 1
#define NORMAL 0
#define FAIL -1

#define HOST "localhost"
#define USERNAME "uzio"
#define PASSWORD "19991121"
#define DATABASE "uzio"

/*mysql 链接*/ 
int getData(char ** _user, char **_pwd){

    char *buffer[2];
    
    MYSQL *Pconn;
    MYSQL_RES* Pres;
    MYSQL_ROW Row;
    int ret = 0;
    int numFields, i;


    Pconn = mysql_init(NULL);

    if (!Pconn){
        fprintf(stderr, "mysql_init failed\n");
        return EXIT_FAILURE;
    }

    Pconn = mysql_real_connect(Pconn,HOST,USERNAME,PASSWORD,DATABASE,0,NULL,0);

    if(Pconn){
        printf("Connection success\n");
    }else{
        printf("Connection failed\n") ;
        // return EXIT_FAILURE;          /*BUG : 当前编译的可执行文件缺失该语句, 但不影响测试目标实现. 考虑到angr分析CFG的时间开销过大,故暂不修改*/
    }
    
    char *Req_sql = "select username,password from verify where _id = 1 limit 1";
    ret = mysql_real_query(Pconn, Req_sql, (unsigned int)strlen(Req_sql));

    if(ret){
        printf("Select error:%s\n", mysql_error(Pconn));
    }else{
        Pres = mysql_store_result(Pconn);
        printf("\n++ mysql>>共%d行 ++\n\n", (int)mysql_num_rows(Pres));
        numFields = mysql_num_fields(Pres);
        Row = mysql_fetch_row(Pres);
        *_user = Row[0];
        *_pwd = Row[1];
    }

    mysql_close(Pconn);

    return EXIT_SUCCESS;
}

void pointless(){
    return;
}

int auth(char *u ,char * p){

    char* sql_user;
    char *sql_pwd;

    getData(&sql_user,&sql_pwd);
    
    if ((strcmp(u, sql_user)==0)&&(strcmp(p, sql_pwd)==0)){   //TODO
        return SUCCESS;
    }
    for(int i=0;i<10000000;i++){
        pointless();
    }

    char* stored_u="user";//get_username();
    char* stored_p="pwd";//get_passsword();

    if((strcmp(u, stored_u)==0&&strcmp(p, stored_p)==0)){
        printf("Welcome.\n");
        return NORMAL;
    }else{
        printf("Verification failed.\n");
        return FAIL;
    }
}


char* input(char* msg){
    char* str;
    str=(char *)malloc(10); 
    printf("%s",msg);
    scanf("%s", str);
    return str;
}


int main(){
    puts("Hello!");
    char* usr=input("User:");
    char* pwd=input("Password:");
    char* cmd;
    if(auth(usr,pwd)>0){
        cmd=input("Command:");
        system(cmd);
        free(cmd);
    }

    free(pwd);
    free(usr);
    return 0;
}