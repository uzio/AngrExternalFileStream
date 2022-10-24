#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#define SUCCESS 1
#define NORMAL 0
#define FAIL -1


void pointless(){
    return;
}

int auth(char *u ,char * p){

    char * v[5];
    char buffer[5][10];

    v[0] = buffer[0];
    int i = 0;

    FILE *fp;
    fp = fopen("verify.txt","r");

    if(fp != NULL){
        while (fgets(v[i],10,fp) != NULL)
        {
            int len = strlen(v[i]);
            if(v[i][len-1]=='\n'){ // 消除换行符
                v[i][len-1] = 0;
            }
            i++;
            v[i] = buffer[i];
        }
    }
    else{
        printf("file not exist");
        return FAIL;
    }
    
    if ((strcmp(u, v[0])==0)&&(strcmp(p, v[1])==0)){
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