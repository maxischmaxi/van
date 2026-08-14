#include "claude.h"
#include "cJSON.h"
#include "utils.h"
#include <assert.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static DiscoveryState parse_discovery(cJSON *j) {
    DiscoveryState d = {0};
    cJSON *url = cJSON_GetObjectItem(j, "authorizationServerUrl");
    cJSON *found = cJSON_GetObjectItem(j, "oauthMetadataFound");
    if (cJSON_IsString(url))
        d.authorization_server_url = dup_str(url->valuestring);
    if (cJSON_IsBool(found))
        d.oauth_metadata_found = cJSON_IsTrue(found);
    return d;
}

static McpServer parse_mcp_server(cJSON *j) {
    McpServer s = {0};
    cJSON *name = cJSON_GetObjectItem(j, "serverName");
    cJSON *url = cJSON_GetObjectItem(j, "serverUrl");
    cJSON *tok = cJSON_GetObjectItem(j, "accessToken");
    cJSON *disc = cJSON_GetObjectItem(j, "discoveryState");
    cJSON *cid = cJSON_GetObjectItem(j, "clientId");
    cJSON *ruri = cJSON_GetObjectItem(j, "redirectUri");

    if (cJSON_IsString(name))
        s.server_name = dup_str(name->valuestring);
    if (cJSON_IsString(url))
        s.server_url = dup_str(url->valuestring);
    if (cJSON_IsString(tok))
        s.access_token = dup_str(tok->valuestring);
    if (cJSON_IsString(cid))
        s.client_id = dup_str(cid->valuestring);
    if (cJSON_IsString(ruri))
        s.redirect_uri = dup_str(ruri->valuestring);
    if (cJSON_IsObject(disc))
        s.discovery_state = parse_discovery(disc);
    return s;
}

static McpOAuth parse_mcp_oauth(cJSON *j) {
    McpOAuth map = {NULL, 0};
    if (!cJSON_IsObject(j)) {
        return map;
    }

    size_t n = 0;
    cJSON *child;
    cJSON_ArrayForEach(child, j) n++;

    map.entries = malloc(n * sizeof(McpEntry));
    if (!map.entries) {
        return map;
    }
    map.count = n;

    size_t i = 0;
    cJSON_ArrayForEach(child, j) {
        map.entries[i].key = dup_str(child->string);
        map.entries[i].server = parse_mcp_server(child);
        i++;
    }

    return map;
}

static ClaudeOAuthAccount parse_account(cJSON *j) {
    ClaudeOAuthAccount c = {0};
    cJSON *accountUuid = cJSON_GetObjectItem(j, "accountUuid");
    cJSON *emailAddress = cJSON_GetObjectItem(j, "emailAddress");
    cJSON *organizationUuid = cJSON_GetObjectItem(j, "organizationUuid");
    cJSON *hasExtraUsageEnabled =
        cJSON_GetObjectItem(j, "hasExtraUsageEnabled");
    cJSON *billingType = cJSON_GetObjectItem(j, "billingType");
    cJSON *accountCreatedAt = cJSON_GetObjectItem(j, "accountCreatedAt");
    cJSON *subscriptionCreatedAt =
        cJSON_GetObjectItem(j, "subscriptionCreatedAt");
    cJSON *ccOnboardingFlags = cJSON_GetObjectItem(j, "ccOnboardingFlags");
    cJSON *claudeCodeTrialEndsAt =
        cJSON_GetObjectItem(j, "claudeCodeTrialEndsAt");
    cJSON *claudeCodeTrialDurationDays =
        cJSON_GetObjectItem(j, "claudeCodeTrialDurationDays");
    cJSON *seatTier = cJSON_GetObjectItem(j, "seatTier");
    cJSON *displayName = cJSON_GetObjectItem(j, "displayName");
    cJSON *profileFetchedAt = cJSON_GetObjectItem(j, "profileFetchedAt");
    cJSON *organizationRole = cJSON_GetObjectItem(j, "organizationRole");
    cJSON *workspaceRole = cJSON_GetObjectItem(j, "workspaceRole");
    cJSON *organizationName = cJSON_GetObjectItem(j, "organizationName");
    cJSON *organizationType = cJSON_GetObjectItem(j, "organizationType");
    cJSON *organizationRateLimitTier =
        cJSON_GetObjectItem(j, "organizationRateLimitTier");
    cJSON *userRateLimitTier = cJSON_GetObjectItem(j, "userRateLimitTier");

    if (cJSON_IsString(accountUuid))
        c.accountUuid = dup_str(accountUuid->valuestring);
    if (cJSON_IsString(emailAddress))
        c.emailAddress = dup_str(emailAddress->valuestring);
    if (cJSON_IsString(organizationUuid))
        c.organizationUuid = dup_str(organizationUuid->valuestring);
    if (cJSON_IsBool(hasExtraUsageEnabled))
        c.hasExtraUsageEnabled = hasExtraUsageEnabled->valueint != 0;
    if (cJSON_IsString(billingType))
        c.billingType = dup_str(billingType->valuestring);
    if (cJSON_IsString(accountCreatedAt))
        c.accountCreatedAt = dup_str(accountCreatedAt->valuestring);
    if (cJSON_IsString(subscriptionCreatedAt))
        c.subscriptionCreatedAt = dup_str(subscriptionCreatedAt->valuestring);
    if (cJSON_IsObject(ccOnboardingFlags)) {
        char *flags_str = cJSON_PrintUnformatted(ccOnboardingFlags);
        c.ccOnboardingFlags = dup_str(flags_str);
        free(flags_str);
    }
    if (cJSON_IsString(claudeCodeTrialEndsAt))
        c.claudeCodeTrialEndsAt = dup_str(claudeCodeTrialEndsAt->valuestring);
    if (cJSON_IsString(claudeCodeTrialDurationDays))
        c.claudeCodeTrialDurationDays =
            dup_str(claudeCodeTrialDurationDays->valuestring);
    if (cJSON_IsString(seatTier))
        c.seatTier = dup_str(seatTier->valuestring);
    if (cJSON_IsString(displayName))
        c.displayName = dup_str(displayName->valuestring);
    if (cJSON_IsNumber(profileFetchedAt))
        c.profileFetchedAt = (int64_t)profileFetchedAt->valuedouble;
    if (cJSON_IsString(organizationRole))
        c.organizationRole = dup_str(organizationRole->valuestring);
    if (cJSON_IsString(workspaceRole))
        c.workspaceRole = dup_str(workspaceRole->valuestring);
    if (cJSON_IsString(organizationName))
        c.organizationName = dup_str(organizationName->valuestring);
    if (cJSON_IsString(organizationType))
        c.organizationType = dup_str(organizationType->valuestring);
    if (cJSON_IsString(organizationRateLimitTier))
        c.organizationRateLimitTier =
            dup_str(organizationRateLimitTier->valuestring);
    if (cJSON_IsString(userRateLimitTier))
        c.userRateLimitTier = dup_str(userRateLimitTier->valuestring);

    return c;
}

static ClaudeAiOauth parse_claude_ai_oauth(cJSON *j) {
    ClaudeAiOauth c = {0};
    cJSON *accessToken = cJSON_GetObjectItem(j, "accessToken");
    cJSON *refreshToken = cJSON_GetObjectItem(j, "refreshToken");
    cJSON *expiresAt = cJSON_GetObjectItem(j, "expiresAt");
    cJSON *refreshTokenExpiresAt =
        cJSON_GetObjectItem(j, "refreshTokenExpiresAt");
    cJSON *scopes = cJSON_GetObjectItem(j, "scopes");
    cJSON *subscriptionType = cJSON_GetObjectItem(j, "subscriptionType");
    cJSON *rateLimitTier = cJSON_GetObjectItem(j, "rateLimitTier");

    if (cJSON_IsString(accessToken))
        c.accessToken = dup_str(accessToken->valuestring);
    if (cJSON_IsString(refreshToken))
        c.refreshToken = dup_str(refreshToken->valuestring);
    if (cJSON_IsNumber(expiresAt))
        c.expiresAt = (int64_t)expiresAt->valuedouble;
    if (cJSON_IsNumber(refreshTokenExpiresAt))
        c.refreshTokenExpiresAt = (int64_t)refreshTokenExpiresAt->valuedouble;
    if (cJSON_IsString(subscriptionType))
        c.subscriptionType = dup_str(subscriptionType->valuestring);
    if (cJSON_IsString(rateLimitTier))
        c.rateLimitTier = dup_str(rateLimitTier->valuestring);

    if (cJSON_IsArray(scopes)) {
        c.scopes_count = cJSON_GetArraySize(scopes);
        c.scopes = malloc(c.scopes_count * sizeof(char *));
        if (!c.scopes) {
            c.scopes_count = 0;
            return c;
        }

        size_t i = 0;
        cJSON *item;
        cJSON_ArrayForEach(item, scopes) {
            c.scopes[i] =
                cJSON_IsString(item) ? dup_str(item->valuestring) : NULL;
            i++;
        }
    }

    return c;
}

ClaudeCredentials *parse_claude_credentials(void) {
    char *credentials_path = append_to_home(".claude/.credentials.json");
    if (credentials_path == NULL) {
        LOG_ERR("Could not find claude credentials.");
        LOG_ERR("Please install claude code and sign in to use this tool.");
        return NULL;
    }

    char *claude_path = append_to_home(".claude.json");
    if (claude_path == NULL) {
        LOG_ERR("Could not find claude.json in home directory");
        LOG_ERR("Please install claude code and sign in to use this tool.");
        free(credentials_path);
        return NULL;
    }

    cJSON *credentials_root = parse_json_file(credentials_path);
    if (credentials_root == NULL) {
        LOG_ERR("Failed to parse %s", credentials_path);
        free(credentials_path);
        free(claude_path);
        return NULL;
    }

    cJSON *claude_root = parse_json_file(claude_path);
    if (claude_root == NULL) {
        LOG_ERR("Failed to parse %s", claude_path);
        cJSON_Delete(credentials_root);
        free(credentials_path);
        free(claude_path);
        return NULL;
    }

    ClaudeCredentials *cc = malloc(sizeof(ClaudeCredentials));
    if (!cc) {
        cJSON_Delete(credentials_root);
        cJSON_Delete(claude_root);
        free(credentials_path);
        free(claude_path);
        return NULL;
    }

    cJSON *mcpOauthJson = cJSON_GetObjectItem(credentials_root, "mcpOAuth");
    cJSON *claudeAiOauthJson =
        cJSON_GetObjectItem(credentials_root, "claudeAiOauth");
    cJSON *accountJson = cJSON_GetObjectItem(claude_root, "oauthAccount");

    McpOAuth mcp = parse_mcp_oauth(mcpOauthJson);
    ClaudeAiOauth claude = parse_claude_ai_oauth(claudeAiOauthJson);
    ClaudeOAuthAccount account = parse_account(accountJson);

    cc->mcpOAuth = mcp;
    cc->claudeAiOauth = claude;
    cc->account = account;

    cJSON_Delete(credentials_root);
    cJSON_Delete(claude_root);
    free(credentials_path);
    free(claude_path);
    return cc;
}

static void free_discovery(DiscoveryState *d) {
    free(d->authorization_server_url);
}

static void free_mcp_server(McpServer *s) {
    free(s->server_name);
    free(s->server_url);
    free(s->access_token);
    free(s->client_id);
    free(s->redirect_uri);
    free_discovery(&s->discovery_state);
}

static void free_mcp_oauth(McpOAuth *m) {
    for (size_t i = 0; i < m->count; i++) {
        free(m->entries[i].key);
        free_mcp_server(&m->entries[i].server);
    }
    free(m->entries);
}

void free_claude_ai_oauth(ClaudeAiOauth *c) {
    free(c->accessToken);
    free(c->refreshToken);
    free(c->subscriptionType);
    free(c->rateLimitTier);
    for (size_t i = 0; i < c->scopes_count; i++)
        free(c->scopes[i]);
    free(c->scopes);
}

void free_claude_credentials(ClaudeCredentials *c) {
    if (!c) {
        return;
    }
    free_claude_ai_oauth(&c->claudeAiOauth);
    free_mcp_oauth(&c->mcpOAuth);
    free_claude_oauth_account(&c->account);
    free(c);
}

static cJSON *build_discovery_json(DiscoveryState *d) {
    cJSON *obj = cJSON_CreateObject();
    if (d->authorization_server_url)
        cJSON_AddStringToObject(obj, "authorizationServerUrl",
                                d->authorization_server_url);
    else
        cJSON_AddNullToObject(obj, "authorizationServerUrl");
    cJSON_AddBoolToObject(obj, "oauthMetadataFound", d->oauth_metadata_found);
    return obj;
}

static cJSON *build_mcp_server_json(McpServer *s) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "serverName",
                            s->server_name ? s->server_name : "");
    cJSON_AddStringToObject(obj, "serverUrl",
                            s->server_url ? s->server_url : "");
    cJSON_AddStringToObject(obj, "accessToken",
                            s->access_token ? s->access_token : "");
    cJSON_AddItemToObject(obj, "discoveryState",
                          build_discovery_json(&s->discovery_state));
    cJSON_AddStringToObject(obj, "clientId", s->client_id ? s->client_id : "");
    cJSON_AddStringToObject(obj, "redirectUri",
                            s->redirect_uri ? s->redirect_uri : "");
    return obj;
}

static cJSON *build_mcp_oauth_json(McpOAuth *m) {
    cJSON *obj = cJSON_CreateObject();
    for (size_t i = 0; i < m->count; i++) {
        cJSON *server = build_mcp_server_json(&m->entries[i].server);
        cJSON_AddItemToObject(obj, m->entries[i].key ? m->entries[i].key : "",
                              server);
    }
    return obj;
}

static cJSON *build_claude_ai_oauth_json(ClaudeAiOauth *a) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "accessToken",
                            a->accessToken ? a->accessToken : "");
    cJSON_AddStringToObject(obj, "refreshToken",
                            a->refreshToken ? a->refreshToken : "");
    cJSON_AddNumberToObject(obj, "expiresAt", (double)a->expiresAt);
    cJSON_AddNumberToObject(obj, "refreshTokenExpiresAt",
                            (double)a->refreshTokenExpiresAt);

    cJSON *scopes = cJSON_CreateArray();
    for (size_t i = 0; i < a->scopes_count; i++) {
        cJSON_AddItemToArray(
            scopes, cJSON_CreateString(a->scopes[i] ? a->scopes[i] : ""));
    }
    cJSON_AddItemToObject(obj, "scopes", scopes);

    cJSON_AddStringToObject(obj, "subscriptionType",
                            a->subscriptionType ? a->subscriptionType : "");
    cJSON_AddStringToObject(obj, "rateLimitTier",
                            a->rateLimitTier ? a->rateLimitTier : "");
    return obj;
}

int write_config_to_file(ClaudeCredentials *creds, char *path) {
    if (!creds || !path) {
        return -1;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "claudeAiOauth",
                          build_claude_ai_oauth_json(&creds->claudeAiOauth));
    cJSON_AddItemToObject(root, "mcpOAuth",
                          build_mcp_oauth_json(&creds->mcpOAuth));

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json_str) {
        return -1;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        free(json_str);
        return -1;
    }

    fputs(json_str, f);
    fputc('\n', f);
    fclose(f);

    free(json_str);
    return 0;
}

static cJSON *build_account_json(ClaudeOAuthAccount *a) {
    cJSON *obj = cJSON_CreateObject();

    cJSON_AddStringToObject(obj, "accountUuid",
                            a->accountUuid ? a->accountUuid : "");
    cJSON_AddStringToObject(obj, "emailAddress",
                            a->emailAddress ? a->emailAddress : "");
    cJSON_AddStringToObject(obj, "organizationUuid",
                            a->organizationUuid ? a->organizationUuid : "");
    cJSON_AddBoolToObject(obj, "hasExtraUsageEnabled", a->hasExtraUsageEnabled);
    cJSON_AddStringToObject(obj, "billingType",
                            a->billingType ? a->billingType : "");
    cJSON_AddStringToObject(obj, "accountCreatedAt",
                            a->accountCreatedAt ? a->accountCreatedAt : "");
    cJSON_AddStringToObject(obj, "subscriptionCreatedAt",
                            a->subscriptionCreatedAt ? a->subscriptionCreatedAt
                                                     : "");

    if (a->ccOnboardingFlags) {
        cJSON *flags = cJSON_Parse(a->ccOnboardingFlags);
        if (flags) {
            cJSON_AddItemToObject(obj, "ccOnboardingFlags", flags);
        } else {
            cJSON_AddNullToObject(obj, "ccOnboardingFlags");
        }
    } else {
        cJSON_AddNullToObject(obj, "ccOnboardingFlags");
    }

    if (a->claudeCodeTrialEndsAt)
        cJSON_AddStringToObject(obj, "claudeCodeTrialEndsAt",
                                a->claudeCodeTrialEndsAt);
    else
        cJSON_AddNullToObject(obj, "claudeCodeTrialEndsAt");

    if (a->claudeCodeTrialDurationDays)
        cJSON_AddStringToObject(obj, "claudeCodeTrialDurationDays",
                                a->claudeCodeTrialDurationDays);
    else
        cJSON_AddNullToObject(obj, "claudeCodeTrialDurationDays");

    if (a->seatTier)
        cJSON_AddStringToObject(obj, "seatTier", a->seatTier);
    else
        cJSON_AddNullToObject(obj, "seatTier");

    cJSON_AddStringToObject(obj, "displayName",
                            a->displayName ? a->displayName : "");
    cJSON_AddNumberToObject(obj, "profileFetchedAt",
                            (double)a->profileFetchedAt);
    cJSON_AddStringToObject(obj, "organizationRole",
                            a->organizationRole ? a->organizationRole : "");

    if (a->workspaceRole)
        cJSON_AddStringToObject(obj, "workspaceRole", a->workspaceRole);
    else
        cJSON_AddNullToObject(obj, "workspaceRole");

    cJSON_AddStringToObject(obj, "organizationName",
                            a->organizationName ? a->organizationName : "");
    cJSON_AddStringToObject(obj, "organizationType",
                            a->organizationType ? a->organizationType : "");
    cJSON_AddStringToObject(
        obj, "organizationRateLimitTier",
        a->organizationRateLimitTier ? a->organizationRateLimitTier : "");

    if (a->userRateLimitTier)
        cJSON_AddStringToObject(obj, "userRateLimitTier", a->userRateLimitTier);
    else
        cJSON_AddNullToObject(obj, "userRateLimitTier");

    return obj;
}

int write_account_to_file(ClaudeOAuthAccount *account, char *path) {
    if (!account || !path) {
        return -1;
    }

    cJSON *root = parse_json_file(path);
    if (!root) {
        root = cJSON_CreateObject();
    }

    cJSON *existing = cJSON_DetachItemFromObject(root, "oauthAccount");
    if (existing) {
        cJSON_Delete(existing);
    }

    cJSON_AddItemToObject(root, "oauthAccount", build_account_json(account));

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json_str) {
        return -1;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        free(json_str);
        return -1;
    }

    fputs(json_str, f);
    fputc('\n', f);
    fclose(f);

    free(json_str);
    return 0;
}

void free_claude_oauth_account(ClaudeOAuthAccount *a) {
    free(a->accountUuid);
    free(a->emailAddress);
    free(a->organizationUuid);
    free(a->billingType);
    free(a->accountCreatedAt);
    free(a->subscriptionCreatedAt);
    free(a->ccOnboardingFlags);
    free(a->claudeCodeTrialEndsAt);
    free(a->claudeCodeTrialDurationDays);
    free(a->seatTier);
    free(a->displayName);
    free(a->organizationRole);
    free(a->workspaceRole);
    free(a->organizationName);
    free(a->organizationType);
    free(a->organizationRateLimitTier);
    free(a->userRateLimitTier);
}

struct response_buf {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
    size_t realsize = size * nmemb;
    struct response_buf *buf = (struct response_buf *)userp;

    char *tmp = realloc(buf->data, buf->size + realsize + 1);
    if (!tmp)
        return 0; // 0 signalisiert Fehler an libcurl

    buf->data = tmp;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';
    return realsize;
}

char *fetch_account_email(const char *access_token) {
    if (!access_token)
        return NULL;

    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s",
             access_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);

    struct response_buf buf = {0};

    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://api.anthropic.com/api/claude_cli/bootstrap");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) {
        free(buf.data);
        return NULL;
    }

    cJSON *root = cJSON_Parse(buf.data);
    free(buf.data);
    if (!root)
        return NULL;

    cJSON *account = cJSON_GetObjectItem(root, "oauth_account");
    char *result = NULL;
    if (account) {
        cJSON *email = cJSON_GetObjectItem(account, "account_email");
        if (cJSON_IsString(email)) {
            result = dup_str(email->valuestring);
        }
    }
    cJSON_Delete(root);
    return result;
}
