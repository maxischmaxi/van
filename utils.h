#ifndef UTILS_H
#define UTILS_H

#include "cJSON.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

// === LOGGING ===
// Design: Ein static inline Helper pro Level + ein dünnnes Macro, das
// __FILE__, __LINE__, __func__ am Aufrufort einfängt.
//
// Warum static inline + Macro statt reinem Macro?
//  1. __attribute__((format(printf, ...))) braucht eine echte Funktion,
//     damit der Compiler %d vs %s Mismatches zur Compile-Zeit prüft.
//  2. __VA_ARGS__ ohne ## vermeidet -Wpedantic Warnungen (GNU-Erweiterung).
//     LOG_ERR(...) übergibt immer >= 1 Argument an __VA_ARGS__.
//  3. static inline im Header = kein Linking, keine Multiple-Definition,
//     wird vom Compiler inline eingefügt (zero overhead).

__attribute__((format(printf, 4, 5))) static inline void
log_err_impl(const char *file, int line, const char *func, const char *fmt,
             ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s:%d] %s: ", file, line, func);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

__attribute__((format(printf, 1, 2))) static inline void
log_warn_impl(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("[WARN] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

__attribute__((format(printf, 1, 2))) static inline void
log_info_impl(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("[INFO] ", stdout);
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    va_end(ap);
}

#define LOG_ERR(...) log_err_impl(__FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_WARN(...) log_warn_impl(__VA_ARGS__)
#define LOG_INFO(...) log_info_impl(__VA_ARGS__)

// === safe_len ===
// Macro statt Funktion: muss im Header stehen, damit alle .c-Dateien
// es sehen. NULL-safe wie das originale Funktions-Äquivalent.
#define safe_len(s) ((s) ? strlen(s) : 0)

char *append_to_home(char *suffix);
int read_file(const char *restrict path, char **restrict out_buf,
              size_t *restrict out_size);
int mkdir_p(const char *path, mode_t mode);
bool is_dir(const char *path);
bool is_file(const char *path);
char *dup_str(const char *s);
char **str_split(const char *s, char delim, size_t *out_count);
char *str_array_to_str(char **elements, size_t count, char *delimiter);
cJSON *parse_json_file(char *path);
bool prompt_yes_no(const char *msg);
char *prompt(const char *msg);
char *ms_to_timestamp(int64_t timestamp, char *buf, size_t len);
int int64_len(int64_t val);
int64_t now_ms(void);
#endif
