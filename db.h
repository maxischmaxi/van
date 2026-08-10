#ifndef DB_H
#define DB_H
#include "claude.h"
#include "sqlite3.h"
#include <stdint.h>

typedef struct {
    int64_t id;
    char *name;
    char *accessToken;
    char *refreshToken;
    int64_t expiresAt;
    int64_t refreshTokenExpiresAt;
    char **scopes;
    size_t scopes_count;
    char *subscriptionType;
    char *rateLimitTier;
} InternalAuth;

InternalAuth **get_all_claude_oauth_configs(size_t *out_size);
uint64_t insert_auth(ClaudeAiOauth auth, char *name);
void free_internal_auth(InternalAuth *auth);
InternalAuth *get_auth_by_name(char *name);
uint32_t delete_auth(uint64_t id);
uint32_t rename_auth(uint64_t id, char *name);
InternalAuth *get_auth_by_id(uint64_t id);
#endif
