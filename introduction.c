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
    if ((strcmp(u, "GO")==0)&&(strcmp(p, "ON")==0)){
        return SUCCESS;
    }
    for(int i=0;i<10000000;i++){
        pointless();
    }

    char* stored_u="user";//get_username();
    char* stored_p="pwd";//get_passsword();

    if((strcmp(u, stored_u)==0&&strcmp(p, stored_p)==0)){
        return NORMAL;
    }else{
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

// char* get_username(){

// }

// char* get_passsword(){

// }

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