//
// Created by yushaye on 2019/11/13.
//

#include <stdio.h>
#ifndef MBEDTLS_READ_CONFIG_H
#define MBEDTLS_READ_CONFIG_H
#endif //MBEDTLS_READ_CONFIG_H


/* 该配置项只能有一个，重复会报错 */
#define CONF_SINGLE       1
/* 该配置项可以设置多个且都有效，如设置DNS的nameserver */
#define CONF_MULTIPLE     2
/* 配置文件中，第一个配置项有效，忽略后面重复的配置项 */
#define CONF_FIRST_VALID  3
/* 配置文件中，最后一个配置项有效，忽略前面重复的配置项 */
#define CONF_LAST_VALID   4

#define MAX_BUF_SIZE      1000

typedef struct conf_s
{
    const char *key; /* conf keyword */
    const int   type;
    const char *connector; /* join fields by connector characters */
    char       *value;
} conf_t;

int parse(FILE *fp, conf_t *cf);