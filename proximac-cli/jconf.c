//
//  jconf.c
//  proximac
//
//  Created by jedihy on 15-5-12.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include "tree.h"
#include "js0n.h"
#include "utils.h"
#include "jconf.h"
#include "local.h"

void read_conf(char* configfile, conf_t* conf)
{
    char* val = NULL;
    char* configbuf = NULL;
    char localport_buf[6] = { 0 };
    char proximac_port_buf[6] = { 0 };
    char vpn_mode_buf[6] = { 0 };
    int vlen = 0;
    
    /* need to reset these bufs to zero */

    FILE* f = fopen(configfile, "rb");
    if (f == NULL) {
        FATAL("Invalid config path.");
    }

    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);

    configbuf = malloc(pos + 1);
    if (configbuf == NULL) {
        FATAL("No enough memory.");
    }

    int nread = fread(configbuf, pos, 1, f);
    if (!nread) {
        FATAL("Failed to read the config file.");
    }
    fclose(f);

    configbuf[pos] = '\0'; // end of string

#define JSONPARSE(str)                                        \
    val = js0n(str, strlen(str), configbuf, (int)pos, &vlen); \
    if (val != NULL)

    JSONPARSE("process_name")
    {
        int index = 0;
        char* buf;
        LOGI("Process List:");
        while ((buf = js0n(NULL, index, val, (int)pos, &vlen)) != NULL) {
            index++;
#define MAX_PROC_NAME_LEN 16
            struct pid* pid_to_insert = malloc(sizeof(struct pid));
            pid_to_insert->name = calloc(1, vlen + 1);
            memcpy(pid_to_insert->name, buf, vlen);
            pid_to_insert->name[vlen] = '\0';
            pid_to_insert->pid = hash(pid_to_insert->name);
            RB_INSERT(pid_tree, &pid_list, pid_to_insert);
            LOGI("%d. %s hash %d", index, pid_to_insert->name, pid_to_insert->pid);
        }

        conf->total_process_num = index;
    }

    JSONPARSE("proximac_port")
    {
        memcpy(proximac_port_buf, val, vlen);
        conf->proximac_port = atoi(proximac_port_buf);
    }
    
    JSONPARSE("VPN_mode")
    {
        memcpy(vpn_mode_buf, val, vlen);
        conf->vpn_mode = atoi(vpn_mode_buf);
    }

    JSONPARSE("proxyapp_name")
    {
        struct pid* proxyapp_hash = malloc(sizeof(struct pid));
        proxyapp_hash->name = calloc(1, vlen + 1);
        memcpy(proxyapp_hash->name, val, vlen);
        proxyapp_hash->name[vlen] = '\0';
        proxyapp_hash->pid = hash(proxyapp_hash->name);
        LOGI("Proxy App name is %s", proxyapp_hash->name);
        LOGD("Proxy App name is %s, hash %d", proxyapp_hash->name, proxyapp_hash->pid);

        conf->proxyapp_hash = proxyapp_hash->pid;
        free(proxyapp_hash);
    }
    
    JSONPARSE("local_port")
    {
        memcpy(localport_buf, val, vlen);
        conf->localport = atoi(localport_buf);
    }

    JSONPARSE("local_address")
    {
        conf->local_address = (char*)malloc(vlen + 1);
        memcpy(conf->local_address, val, vlen);
        conf->local_address[vlen] = '\0';
    }

    JSONPARSE("username")
    {
        conf->username = (char*)malloc(vlen + 1);
        memcpy(conf->username, val, vlen);
        conf->username[vlen] = '\0';
    }

    JSONPARSE("password")
    {
        conf->password = (char*)malloc(vlen + 1);
        memcpy(conf->password, val, vlen);
        conf->password[vlen] = '\0';
    }

#undef JSONPARSE

    free(configbuf);
}