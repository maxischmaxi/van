#ifndef CLAUDE_H
#define CLAUDE_H

#include "cJSON.h"
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
    ClaudeAiOauth claudeAiOauth;
    McpOAuth mcpOAuth;
} ClaudeCredentials;

ClaudeCredentials *parse_claude_credentials(cJSON *root);
void free_claude_credentials(ClaudeCredentials *c);
void free_claude_ai_oauth(ClaudeAiOauth *c);
int write_config_to_file(ClaudeCredentials *creds, char *path);
#endif
