#ifndef CMD_H
#define CMD_H
#include "claude.h"
int run_list(void);
int run_add(ClaudeCredentials *current_cred);
int run_delete(void);
int run_show(ClaudeCredentials *current_cred);
int run_rename(ClaudeCredentials *current_cred);
int run_swap(ClaudeCredentials *current_cred, char *path);
#endif
