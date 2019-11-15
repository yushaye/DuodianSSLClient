#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/ssl.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif


#include "util/read_config.h"
#include "util/md5.h"

#define SSL_MAX_CONTENT_LEN 1024 //每次最大数据传输量
void string_to_md5(char* str, int strlen,unsigned char out_put[32]) {
    unsigned char a[16] = { 0 };
    md5_context ctx;
    md5_init(&ctx);
    md5_starts(&ctx);
    md5_update(&ctx, str, strlen);
    md5_finish(&ctx, a);
    md5_free(&ctx);
    for (int i = 0; i < 16; i++)
    {
        snprintf(&out_put[i * 2], 32,"%02x", a[i]);
    }
}

void get_date(unsigned char out_put[19]) {
    time_t timep;
    struct tm* p;
    time(&timep);
    p = gmtime(&timep);
    snprintf(out_put,19, "%04d-%02d-%02d %02d:%02d:%02d", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, 8 + p->tm_hour, p->tm_min, p->tm_sec);
}

int get_time() {
    time_t t;
    t = time(NULL);

    return time(&t);
}

void get_login_request(unsigned char request[SSL_MAX_CONTENT_LEN],int* len, FILE *conf_file) {
#define MAX_VALUE_LEN 1000

    char* api = "/";
    char Uip[MAX_VALUE_LEN] = {0};
    unsigned int content_len=0;
    char host[MAX_VALUE_LEN] = {0};
    char account[MAX_VALUE_LEN] = {0};
    char password[MAX_VALUE_LEN] = {0};
    char ssid[MAX_VALUE_LEN] = {0};
    char loginIP[MAX_VALUE_LEN] = {0};
    char mac[MAX_VALUE_LEN] = {0};


    struct conf_s conf[]={
            {"account",CONF_SINGLE,NULL,account},
            {"password",CONF_SINGLE,NULL,password},
            {"ssid",CONF_SINGLE,NULL,ssid},
            {"mac",CONF_SINGLE,NULL,mac},
            {"loginIP",CONF_SINGLE,NULL,loginIP},
            {"host",CONF_SINGLE,NULL,host}

    };
    parse(conf_file,conf);
    if(strlen(account) == 0){
        printf("account not provided in the config file exit\n");
        fflush(stdout);
        getchar();
        exit(0);
    }
    if(strlen(password) == 0){
        printf("password not provided in the config file exit\n");
        fflush(stdout);
        getchar();
        exit(0);
    }
    if(strlen(ssid) == 0){
        strcpy(ssid,"CQU_WiFi");
    }
    if(strlen(mac) == 0){
        strcpy(mac,"14:1D:14:14:13:1E");
    }
    if(strlen(loginIP) == 0){
        strcpy(loginIP,"192.168.1.123");
    }
    if(strlen(host) == 0){
        strcpy(host,"202.202.0.163");
    }
    fflush(stdout);

    char content[SSL_MAX_CONTENT_LEN] = {0};
    snprintf(content,SSL_MAX_CONTENT_LEN, "DDDDD=%s&upass=%s&m1=%s&0MKKey=0123456789&ssid=%s&ver=1.3.5.201603281.G.L.A&sim_sp=cm&cver1=1&cver2=10510000&sIP=192.168.1.253\r\n", \
		account, password,mac,ssid);
    fflush(stdout);

    char md5_str1[MAX_VALUE_LEN];
    char md5_str2[MAX_VALUE_LEN];

    unsigned char date[19] = { 0 };
    get_date(date);
    int time_now = get_time();
    snprintf(md5_str1,MAX_VALUE_LEN, "%s%s", \
		content,date);
    snprintf(md5_str2,MAX_VALUE_LEN, "%s%d", \
		content, time_now);

    unsigned char  md5_1[33];
    unsigned char  md5_2[33];
    string_to_md5(md5_str1, strlen(md5_str1), md5_1);
    string_to_md5(md5_str2, strlen(md5_str2), md5_2);
    snprintf(Uip,MAX_VALUE_LEN, "va5=1.2.3.4.%s%c%c%c%c%c%c%c%c", md5_1, md5_2[0], md5_2[1], md5_2[6], md5_2[7], md5_2[20], md5_2[21], md5_2[26], md5_2[27]);
    //char request[SSL_MAX_CONTENT_LEN];
    snprintf(request,SSL_MAX_CONTENT_LEN,"POST %s HTTP/1.1\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\n"
                     "Charset: utf-8\r\n"
                     "Date: %s\r\n"
                     "Time: %d\r\n"
                     "Uip: %s\r\n"
                     "Content-Length: %d\r\n"
                     "Host: %s\r\n"
                     "User-Agent: DrCOM-HttpClient\r\n"
                     "\r\n"
                     "%s", api, date, time_now, Uip, strlen(content), host, content);

    fflush(stdout);
    *len = strlen(request);
    request[*len] = '\0';
}

char* strstrc(char* pp,char* pd)
{
    char *sou = pp;
    char *des = pd;
    if(*sou == NULL||*pd ==NULL)
        return NULL;
    while((*sou!=NULL)&&(*des!=NULL))
    {
        if(*sou==*des)
        {
            char* ts = sou;
            char* td = des;
            ts++;
            td++;
            while((*ts!=NULL)&&(*td!=NULL))
            {
                if(*ts==*td)
                {
                    ts++;
                    td++;
                }
                else
                    break;
            }
            if(*td==NULL)
            {
                des = td;
                break;
            }
            else
            {
                sou++;
            }
        }
        else
        {
            sou++;
        }
    }
    if(*des==NULL)
        return sou;
    return NULL;
}

void printError(int Msg,char * cMsg){
    printf("\n登录返回信息：\n");
    switch(Msg){
        case 0:
            break;
        case 1:
            if(strstrc(cMsg,"userid error1") != NULL){
                printf("账号不存在\n");
            }else if(strstrc(cMsg,"userid error2") != NULL){
                printf("本IP不允许Web方式登录\n");
            }
            else if(strstrc(cMsg,"userid error3") != NULL){
                printf("密码输入错误\n");
            }
            else if(strstrc(cMsg,"error0") != NULL){
                printf("本IP不允许Web方式登录\n");
            }
            else if(strstrc(cMsg,"error1") != NULL){
                printf("本账号不允许Web方式登录\n");
            }
            else if(strstrc(cMsg,"error2") != NULL){
                printf("本账号不允许修改密码\n");
            } else{
                printf("%s\n", cMsg);
            }
            break;
        case 2:
            printf("该账号正在使用中，请您与网管联系\n");
            break;
        case 3:
            printf("本账号只能在指定地址使用\nThis account can be used on the appointed address only.\n");
            break;
        case 4:
            printf("本账号费用超支或时长流量超过限制\n");
            break;
        case 5:
            printf("本账号暂停使用\n");
            break;
        case 6:
            printf("System buffer full\n");
            break;
        case 8:
            printf("本账号正在使用,不能修改\n");
            break;
        case 9:
            printf("新密码与确认新密码不匹配,不能修改\n");
            break;
        case 10:
            printf("密码修改成功\n");
            break;
        case 11:
            printf("本账号只能在指定地址使用 \n");
            break;
        case 7:

            break;
        case 14:
            printf("注销成功\n");
            break;
        case 15:
            printf("登录成功\n");
            break;
    }
    fflush(stdout);
}

int findStrBetween(char* buf,char* firstStr,char* secondStr,char result[100]){
    char* p = strstrc(buf,firstStr);
    char* q;
    if(p != NULL){
        p += strlen(firstStr);
        q = strstrc(p,secondStr);
        if(q!=NULL){
            int len = q-p;
            for(int i=0;i<len;i++){
                result[i] = p[i];
            }
            result[len] = '\0';
            return  0;
        }
    }
    return -1;
}

void ShowCerts(SSL * ssl){
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("无证书信息！\n");
}

int main(int argc, char *argv[]){

    char config_path[100] = {0};
    for(int i = 1;i<argc;i++){
        if(argv[i][0] == '-' && i < (argc-1)){
            if(argv[i][1] == 'c' || argv[i][1] == 'C'){
                strcpy(config_path, argv[i+1]);
            }
        }
    }
    const char *dft_etc_path = "/etc/duodian.conf";
    const char *dft_path = "./duodian.conf";
    if(strlen(config_path) == 0){
        printf("No config file setted, try \"%s\"\n",dft_etc_path);
        fflush(stdout);
        strcpy(config_path, dft_etc_path);

        if(access(config_path, F_OK) == -1){
            printf("\"%s\" do not exist, try \"%s\"\n",dft_etc_path, dft_path);
            fflush(stdout);
            strcpy(config_path, dft_path);
        }

        if(access(config_path, F_OK) == -1){
            printf("\"%s\" do not exist, exit\n", dft_path);
            fflush(stdout);
            exit(0);
        }
    } else if(access(config_path, F_OK) == -1){
        printf("%s do not exist, try \"%s\"\n",config_path, dft_etc_path);
        fflush(stdout);
        strcpy(config_path, dft_etc_path);

        if(access(config_path, F_OK) == -1){
            printf("\"%s\" do not exist, try \"%s\"\n",dft_etc_path, dft_path);
            fflush(stdout);
            strcpy(config_path, dft_path);
        }

        if(access(config_path, F_OK) == -1){
            printf("\"%s\" do not exist, exit\n", dft_path);
            fflush(stdout);
            exit(0);
        }
    }

    char *hostname="127.0.0.1";
    int sendResult;
    int sockfd;
    char clientbuf[SSL_MAX_CONTENT_LEN];
    struct hostent *host;//gethostbyname函数的参数返回
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        //ERR_print_errors_fp(stdout);
        exit(1);
    }

#ifdef WIN32
    WSADATA wsaData;
    // 1 启动并初始化winsock(WSAStarup)
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))//成功返回0
    {
        return FALSE;
    }
#endif

    memset(&serv_addr,0, sizeof(serv_addr));
    sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    serv_addr.sin_family = AF_INET;

#ifdef WIN32
    serv_addr.sin_addr.S_un.S_addr = inet_addr("202.202.0.163");
#else
    serv_addr.sin_addr.s_addr = inet_addr("202.202.0.163");
#endif


    serv_addr.sin_port = htons(443);
    int c = connect(sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if( c!= 0){
        printf("socket connect failed:%d\n",c);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) == -1)
        //ERR_print_errors_fp(stderr);
        printf("error\n");
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        //ShowCerts(ssl);
    }

    memset(clientbuf,0, SSL_MAX_CONTENT_LEN);
    int len = 0;
    FILE* conf_file=NULL;
    conf_file = fopen(config_path,"r");
    get_login_request(clientbuf,&len,conf_file);

    sendResult = SSL_write(ssl, clientbuf, len);

    if (sendResult < 0)
        printf("\n登录信息:\n%s发送失败！错误代码是%d，错误信息是'%s'\n",clientbuf, errno, strerror(errno));
    else
        printf("\n登录信息:\n%s\n发送成功，共发送了%d个字节！\n",clientbuf, sendResult);
    memset(clientbuf,0,SSL_MAX_CONTENT_LEN);
    while(1){
        int readReslut = SSL_read(ssl, clientbuf, SSL_MAX_CONTENT_LEN - 1);
        if(readReslut > 0){
            char new_buf[readReslut];
            clientbuf[readReslut] = '\0';
            snprintf(new_buf,readReslut, "%s",clientbuf);
            //登录成功 in gb2312
            char login_s[100] = {0xb5,0xc7,0xc2,0xbc,0xb3,0xc9,0xb9,0xa6};
            //信息返回 in gb2312
            char login_e[100] = {0xd0,0xc5,0xcf,0xa2,0xb7,0xb5,0xbb,0xd8};
            if(strstrc((char*)new_buf,login_s) != NULL){
                printf("\n\n登录成功\n\n");
                break;
            }else{
                if(strstrc((char*)new_buf,login_e) != NULL){
                    char cMsg[100];
                    findStrBetween(new_buf, "Msg=", "msga=\'", cMsg);
                    findStrBetween(new_buf, "Msg=", ";", cMsg);
                    int Msg = atoi(cMsg);
                    findStrBetween(new_buf, "msga=\'", "\';", cMsg);
                    printError(Msg,cMsg);
                    break;
                }
            }
            memset(clientbuf,0,SSL_MAX_CONTENT_LEN);
        } else{
            printf("read from server error exit\n");
            exit(0);
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    printf("\n按任意键退出程序\n");
    fflush(stdout);
    getchar();
    return 1;
}