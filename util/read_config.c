//
// Created by yushaye on 2019/11/13.
//

// config.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "read_config.h"

char *trim_left_right(char *s)
{
    char *e;

    /* 去除开头的空白 */
    while (isspace(*s)) s++;

    /* 结尾空白全部置为\0 */
    e = s + strlen(s) - 1;
    while (isspace(*e) && e > s) {
        *e = '\0';
        e--;
    }
    if (e == s) {
        *e = '\0';
    }

    return s;
}

int isdelimiter(char c)
{
    if (isspace(c) || c == '=' || c == ':' ) {
        return 1;
    } else {
        return 0;
    }
}

int set_conf(conf_t *conf, char *key, char *value)
{
    conf_t *p;

    if (key == NULL || value == NULL || conf == NULL) {
        return 0;
    }

    for (p = conf; p->key != NULL; p++)
    {
        if (strcasecmp(key, p->key) == 0 && p->value) {
            switch (p->type) {
                case CONF_MULTIPLE:
                    if (*p->value != '\0') {
                        /* 存在重复项时，使用connector拼接 */
                        snprintf(p->value, MAX_BUF_SIZE,"%s%s%s", p->value, p->connector, value);
                    } else {
                        snprintf(p->value,MAX_BUF_SIZE,"%s", value);
                    }
                    break;
                case CONF_SINGLE:
                    if (*p->value != '\0') {
                        printf("ERROR: keyword \"%s\" is duplicate\n", key);
                        return 0;
                    } else {
                        snprintf(p->value, MAX_BUF_SIZE,"%s", value);
                    }
                    break;
                case CONF_FIRST_VALID:
                    if (*p->value == '\0') {
                        snprintf(p->value,MAX_BUF_SIZE, "%s", value);
                    }
                    break;
                case CONF_LAST_VALID:
                    snprintf(p->value,MAX_BUF_SIZE, "%s", value);
                    break;
            }

            return 1;
        }
    }
    printf("ERROR: unknown keyword \"%s\"\n", key);
    return 0;
}

int parse(FILE *fp, conf_t *cf)
{
    char buf[MAX_BUF_SIZE], *key, *value, *tmp;

    memset(buf, 0, MAX_BUF_SIZE);

    while (fgets(buf, MAX_BUF_SIZE, fp) != NULL)
    {
        /* 去除#号及其之后的字符 */
        tmp = buf;
        while (*tmp != '#' && *tmp != '\0') {
            tmp++;
        }
        if (*tmp == '#') {
            *tmp = '\0';
        }

        /* 去除前后的空白符 */
        key = trim_left_right(buf);

        if (*key == '\0') {
            memset(buf, 0, MAX_BUF_SIZE);
            continue;
        }

        /* 使用\0设置key和value之间的分隔符，即可取出key，并得到value的起始位置 */
        value = key;
        while (!isdelimiter(*value) && *value != '\0') {
            value++;
        }
        while (isdelimiter(*value) && *value != '\0') {
            *value = '\0';
            value++;
        }

        if (*value == '\0') {
            printf("ERROR: no value for keyword \"%s\"\n", key);
            memset(buf, 0, MAX_BUF_SIZE);
            continue;
        }

        if (!set_conf(cf, key, value)) {
            return 0;
        }

        memset(buf, 0, MAX_BUF_SIZE);
    }

    return 1;
}
