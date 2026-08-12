#ifndef UTILS_H
#define UTILS_H
#include "cJSON.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
char *append_to_home(char *suffix);
int read_file(const char *path, char **out_buf, size_t *out_size);
int mkdir_p(const char *path, mode_t mode);
bool is_dir(const char *path);
bool is_file(const char *path);
char *dup_str(const char *s);
char **str_split(const char *s, char delim, size_t *out_count);
char *str_array_to_str(char **elements, size_t count, char *delimiter);
cJSON *parse_credentials_file(char *path);
bool prompt_yes_no(const char *msg);
char *prompt(const char *msg);
char *ms_to_timestamp(int64_t timestamp, char *buf, size_t len);
int int64_len(int64_t val);
size_t safe_len(const char *s);
#endif
