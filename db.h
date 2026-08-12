#ifndef DB_H
#define DB_H
#include "claude.h"
#include "sqlite3.h"
#include <stdint.h>

typedef struct {
    // .claude/.credentials.json
    int64_t id;
    char *accessToken;
    char *refreshToken;
    int64_t expiresAt;
    int64_t refreshTokenExpiresAt;
    char **scopes;
    size_t scopes_count;
    char *subscriptionType;
    char *rateLimitTier;

    // .claude.json
    char *accountUuid;
    char *emailAddress;
    char *organizationUuid;
    bool hasExtraUsageEnabled;
    char *billingType;
    char *accountCreatedAt;            // timestamp
    char *subscriptionCreatedAt;       // timestamp
    char *ccOnboardingFlags;           // {}
    char *claudeCodeTrialEndsAt;       // null
    char *claudeCodeTrialDurationDays; // null
    char *seatTier;                    // null
    char *displayName;
    int64_t profileFetchedAt;
    char *organizationRole;
    char *workspaceRole; // null
    char *organizationName;
    char *organizationType;
    char *organizationRateLimitTier;
    char *userRateLimitTier; // null
} InternalAuth;

InternalAuth **get_all_claude_oauth_configs(size_t *out_size);
uint64_t insert_auth(ClaudeAiOauth auth, ClaudeOAuthAccount account);
void free_internal_auth(InternalAuth *auth);
uint32_t delete_auth(uint64_t id);
InternalAuth *get_auth_by_id(uint64_t id);
InternalAuth *get_auth_by_email(char *email);
#endif
