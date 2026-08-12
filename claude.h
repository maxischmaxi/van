#ifndef CLAUDE_H
#define CLAUDE_H

#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    char *accessToken;
    char *refreshToken;
    int64_t expiresAt;
    int64_t refreshTokenExpiresAt;
    char **scopes;
    size_t scopes_count;
    char *subscriptionType;
    char *rateLimitTier;
} ClaudeAiOauth;

typedef struct {
    char *authorization_server_url;
    int oauth_metadata_found;
} DiscoveryState;

typedef struct {
    char *server_name;
    char *server_url;
    char *access_token;
    DiscoveryState discovery_state;
    char *client_id;
    char *redirect_uri;
} McpServer;

typedef struct {
    char *key;
    McpServer server;
} McpEntry;

typedef struct {
    McpEntry *entries;
    size_t count;
} McpOAuth;

typedef struct {
    char *accountUuid;
    char *emailAddress;
    char *organizationUuid;
    bool hasExtraUsageEnabled;
    char *billingType;
    char *accountCreatedAt;
    char *subscriptionCreatedAt;
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
} ClaudeOAuthAccount;

typedef struct {
    ClaudeAiOauth claudeAiOauth;
    McpOAuth mcpOAuth;
    ClaudeOAuthAccount account;
} ClaudeCredentials;

ClaudeCredentials *parse_claude_credentials(void);
void free_claude_credentials(ClaudeCredentials *c);
void free_claude_ai_oauth(ClaudeAiOauth *c);
void free_claude_oauth_account(ClaudeOAuthAccount *a);
int write_config_to_file(ClaudeCredentials *creds, char *path);
int write_account_to_file(ClaudeOAuthAccount *account, char *path);
char *fetch_account_email(const char *access_token);
#endif
