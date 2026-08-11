#include "claude.h"
#include "cJSON.h"
#include "utils.h"
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

ClaudeCredentials *parse_claude_credentials(cJSON *root) {
    if (root == NULL) {
        return NULL;
    }
    ClaudeCredentials *c = malloc(sizeof(ClaudeCredentials));
    if (!c) {
        return NULL;
    }
    cJSON *mcpOauth = cJSON_GetObjectItem(root, "mcpOAuth");
    cJSON *claudeAiOauth = cJSON_GetObjectItem(root, "claudeAiOauth");

    McpOAuth mcp = parse_mcp_oauth(mcpOauth);
    ClaudeAiOauth claude = parse_claude_ai_oauth(claudeAiOauth);

    c->mcpOAuth = mcp;
    c->claudeAiOauth = claude;

    return c;
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
