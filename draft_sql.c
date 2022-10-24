#include<stdio.h>
#include<string.h>
#include<mysql/mysql.h>

#define HOST "localhost"
#define USERNAME "uzio"
#define PASSWORD "19991121"
#define DATABASE "uzio"

// void query_sql(MYSQL *conn, char *sql){
//     int res;
//     MYSQL_RES *res_ptr;
//     MYSQL_FIELD *field;
//     MYSQL_ROW result_row;
//     int row, col;
//     int i, j;

//     if(res){
//         printf("ERROR: mysql_query failed\n");
//         mysql_close(conn);
//     }
//     else{
//         res_ptr  = mysql_store_result(conn);
//         if(res_ptr){
//             col = mysql_num_fields(res_ptr);
//             row = mysql_num_rows(res_ptr);
//             printf("result found in Row %d\n",row);
            
//             for(i = 0; (field = mysql_fetch_field(res_ptr)); i++){
//                 printf("%10s",field->name);
//             }
//             printf("\n");
//             for(i=0; i < row+1; i++){
//                 result_row = mysql_fetch_row(res_ptr);
//                 for(j = 0; j < col; j++){
//                     printf("%10s",result_row[j]);
//                 }
//                 printf("\n");
//             }
//         }
//     }
// }

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
    }
    
    char *Req_sql = "select username,password from verify where _id = 1 limit 1";
    ret = mysql_real_query(Pconn, Req_sql, (unsigned int)strlen(Req_sql));

    if(ret){
        printf("Select error:%s\n", mysql_error(Pconn));
    }else{
        Pres = mysql_store_result(Pconn);
        printf("共%d行\n", (int)mysql_num_rows(Pres));
        numFields = mysql_num_fields(Pres);
        Row = mysql_fetch_row(Pres);
        *_user = Row[0];
        *_pwd = Row[1];
    }

    mysql_close(Pconn);

    return EXIT_SUCCESS;
}

int main(){
    char *user ;
    char *pwd ;
    getData(&user,&pwd);
    printf("user> %s\npwd> %s\n",user,pwd);
}