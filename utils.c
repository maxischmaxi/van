#define _POSIX_C_SOURCE 200809L
#include "utils.h"
#include "cJSON.h"
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *home(void) {
    const char *home = getenv("HOME");
    if (home && home[0] != '\0') {
        return home;
    }
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        return pw->pw_dir;
    }
    return NULL;
}

char *append_to_home(char *suffix) {
    if (suffix == NULL) {
        return NULL;
    }

    const char *sep = suffix[0] == '/' ? "" : "/";

    const char *homedir = home();
    if (homedir == NULL) {
        return NULL;
    }

    size_t n = strlen(homedir) + strlen(suffix) + 2;
    char *path = malloc(n);
    if (!path) {
        return NULL;
    }

    snprintf(path, n, "%s%s%s", homedir, sep, suffix);
    return path;
}

int read_file(const char *path, char **out_buf, size_t *out_size) {
    *out_buf = NULL;
    *out_size = 0;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *data = malloc(size + 1);
    if (!data) {
        fclose(f);
        return -1;
    }

    size_t read = fread(data, 1, size, f);
    data[read] = '\0';
    fclose(f);

    *out_buf = data;
    *out_size = read;

    return 0;
}

int mkdir_p(const char *path, mode_t mode) {
    char tmp[4096];
    size_t len = strlen(path);
    if (len >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, len + 1);

    // Alle '/' durchlaufen und jede Ebene erstellen
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0'; // bis hier abschneiden
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            tmp[i] = '/'; // wieder herstellen
        }
    }

    // Letzte Ebene (kein trailing /)
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

bool is_dir(const char *path) {
    if (!path) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

bool is_file(const char *path) {
    if (!path) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISREG(st.st_mode);
}

char *dup_str(const char *s) {
    if (!s) {
        return NULL;
    }
    char *c = malloc(strlen(s) + 1);
    if (c) {
        strcpy(c, s);
    }
    return c;
}

char **str_split(const char *s, char delim, size_t *out_count) {
    *out_count = 0;
    if (!s) {
        return NULL;
    }

    size_t count = 1;
    for (const char *p = s; *p; p++) {
        if (*p == delim) {
            count++;
        }
    }

    char **result = malloc(count * sizeof(char *));
    if (!result) {
        return NULL;
    }

    size_t idx = 0;
    const char *start = s;
    for (const char *p = s;; p++) {
        if (*p == delim || *p == '\0') {
            size_t len = (size_t)(p - start);
            char *token = malloc(len + 1);
            if (!token) {
                for (size_t i = 0; i < idx; i++) {
                    free(result[i]);
                }
                free(result);
                return NULL;
            }
            memcpy(token, start, len);
            token[len] = '\0';
            result[idx++] = token;

            if (*p == '\0') {
                break;
            }
            start = p + 1;
        }
    }

    *out_count = count;
    return result;
}

char *str_array_to_str(char **elements, size_t count, char *delimiter) {
    char *buf = malloc(1);
    buf[0] = '\0';
    size_t len = 0;
    size_t cap = 1;

    for (size_t i = 0; i < count; i++) {
        const char *sep = i > 0 ? delimiter : "";
        size_t add = strlen(sep) + strlen(elements[i]);

        if (len + add + 1 > cap) {
            while (len + add + 1 > cap)
                cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
        }

        strcpy(buf + len, sep);
        len += strlen(sep);
        strcpy(buf + len, elements[i]);
        len += strlen(elements[i]);
    }

    return buf;
}

cJSON *parse_credentials_file(char *path) {
    char *buf;
    size_t size;

    int success = read_file(path, &buf, &size);
    if (success != 0) {
        return NULL;
    }

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    return root;
}

bool prompt_yes_no(const char *msg) {
    char buf[16];
    for (;;) {
        printf("%s [y/n]: ", msg);
        fflush(stdout);

        if (!fgets(buf, sizeof(buf), stdin))
            return false;

        char c = (char)tolower((unsigned char)buf[0]);
        if (c == 'y')
            return true;
        if (c == 'n')
            return false;

        printf("Bitte 'y' oder 'n' eingeben.\n");
    }
}

char *prompt(const char *msg) {
    printf("%s", msg);
    fflush(stdout); // sicherstellen dass der Prompt sichtbar ist

    char *line = NULL;
    size_t cap = 0;
    ssize_t len = getline(&line, &cap, stdin);
    if (len < 0) {
        free(line);
        return NULL;
    }
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
    }
    return line; // Caller muss free(line) rufen!
}
