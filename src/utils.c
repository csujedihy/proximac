//
//  utils.c
//  proximac
//
//  Created by jedihy on 15-5-12.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "utils.h"

void usage() {
    printf("\
Proximac v1.0\n\
  developed by Jedihy csujedi@icloud.com\n\
  usage:\n\
  proximac\n\
    -c <config_file> Path of configuration file that is written in JSON\n\
    -d daemon mode\n\
    ");
}

void init_daemon() {
    pid_t pid;
    
    /* Fork off the parent process */
    pid = fork();
    
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);
    
    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);
    
    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    /* Fork off for the second time*/
    pid = fork();
    
    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);
    
    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    /* Set new file permissions */
    umask(0);
    
    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("./");
}

// for performance tunning
struct timeval GetTimeStamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv;
}

unsigned int hash(char *str)
{
    unsigned int h;
    unsigned char *p;
    unsigned int i;
#define MULTIPLIER 33
    h = 0;
    i = 0;
    for (p = (unsigned char*)str; (*p != '\0')&&(i < 16); p++,i++)
        h = MULTIPLIER * h + *p;
#undef MULTIPLIER
    return h; // or, h % ARRAY_SIZE;
}