#include "db.h"
#include "cJSON.h"
#include "claude.h"
#include "sqlite3.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELDS_PRE_SCOPES(X)                                                   \
    X(STRING, accessToken, oauth)                                              \
    X(STRING, refreshToken, oauth)                                             \
    X(INT64, expiresAt, oauth)                                                 \
    X(INT64, refreshTokenExpiresAt, oauth)

#define FIELDS_POST_SCOPES(X)                                                  \
    X(STRING, subscriptionType, oauth)                                         \
    X(STRING, rateLimitTier, oauth)                                            \
    X(STRING, accountUuid, account)                                            \
    X(STRING, emailAddress, account)                                           \
    X(STRING, organizationUuid, account)                                       \
    X(BOOL, hasExtraUsageEnabled, account)                                     \
    X(STRING, billingType, account)                                            \
    X(STRING, accountCreatedAt, account)                                       \
    X(STRING, subscriptionCreatedAt, account)                                  \
    X(STRING, ccOnboardingFlags, account)                                      \
    X(STRING, claudeCodeTrialEndsAt, account)                                  \
    X(STRING, claudeCodeTrialDurationDays, account)                            \
    X(STRING, seatTier, account)                                               \
    X(STRING, displayName, account)                                            \
    X(INT64, profileFetchedAt, account)                                        \
    X(STRING, organizationRole, account)                                       \
    X(STRING, workspaceRole, account)                                          \
    X(STRING, organizationName, account)                                       \
    X(STRING, organizationType, account)                                       \
    X(STRING, organizationRateLimitTier, account)                              \
    X(STRING, userRateLimitTier, account)

#define COUNT_FIELD(type, name, src) +1
#define FIELD_COUNT_PRE (0 FIELDS_PRE_SCOPES(COUNT_FIELD))
#define FIELD_COUNT_POST (0 FIELDS_POST_SCOPES(COUNT_FIELD))
#define TOTAL_BIND_PARAMS (FIELD_COUNT_PRE + 1 + FIELD_COUNT_POST)

_Static_assert(
    TOTAL_BIND_PARAMS == 26,
    "X-Macro Feldanzahl stimmt nicht mit SQL-Platzhalter-Anzahl überein");

#define FREE_STRING(p) free(p)
#define FREE_INT64(p) (void)(p)
#define FREE_BOOL(p) (void)(p)

#define DO_FREE(type, name, src) FREE_##type(auth->name);

#define BIND_STRING(s, i, v) sqlite3_bind_text(s, i, v, -1, SQLITE_TRANSIENT)
#define BIND_INT64(s, i, v) sqlite3_bind_int64(s, i, v)
#define BIND_BOOL(s, i, v) sqlite3_bind_int(s, i, v ? 1 : 0)

#define DO_BIND(type, name, src) BIND_##type(stmt, idx++, src->name);

#define READ_STRING(s, c, f)                                                   \
    auth->f = dup_str((const char *)sqlite3_column_text(s, c))
#define READ_INT64(s, c, f) auth->f = sqlite3_column_int64(s, c)
#define READ_BOOL(s, c, f) auth->f = sqlite3_column_int(s, c) != 0

#define DO_READ(type, name, src) READ_##type(stmt, col++, name);

static const char *ALL_COLUMNS = "id, "
                                 "accessToken, "
                                 "refreshToken, "
                                 "expiresAt, "
                                 "refreshTokenExpiresAt, "
                                 "scopes, "
                                 "subscriptionType, "
                                 "rateLimitTier, "
                                 "accountUuid, "
                                 "emailAddress, "
                                 "organizationUuid, "
                                 "hasExtraUsageEnabled, "
                                 "billingType, "
                                 "accountCreatedAt, "
                                 "subscriptionCreatedAt, "
                                 "ccOnboardingFlags, "
                                 "claudeCodeTrialEndsAt, "
                                 "claudeCodeTrialDurationDays, "
                                 "seatTier, "
                                 "displayName, "
                                 "profileFetchedAt, "
                                 "organizationRole, "
                                 "workspaceRole, "
                                 "organizationName, "
                                 "organizationType, "
                                 "organizationRateLimitTier, "
                                 "userRateLimitTier ";

static const char *ALL_COLUMNS_WITHOUT_ID = "accessToken, "
                                            "refreshToken, "
                                            "expiresAt, "
                                            "refreshTokenExpiresAt, "
                                            "scopes, "
                                            "subscriptionType, "
                                            "rateLimitTier, "
                                            "accountUuid, "
                                            "emailAddress, "
                                            "organizationUuid, "
                                            "hasExtraUsageEnabled, "
                                            "billingType, "
                                            "accountCreatedAt, "
                                            "subscriptionCreatedAt, "
                                            "ccOnboardingFlags, "
                                            "claudeCodeTrialEndsAt, "
                                            "claudeCodeTrialDurationDays, "
                                            "seatTier, "
                                            "displayName, "
                                            "profileFetchedAt, "
                                            "organizationRole, "
                                            "workspaceRole, "
                                            "organizationName, "
                                            "organizationType, "
                                            "organizationRateLimitTier, "
                                            "userRateLimitTier ";

static const char *const SQL_GET_ALL = "SELECT %s FROM claude_auth_credentials";

static const char *const SQL_GET_BY_ID =
    "SELECT %s FROM claude_auth_credentials WHERE id = ?";

static const char *const SQL_INSERT =
    "INSERT INTO claude_auth_credentials (%s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

static const char *const SQL_UPDATE_BY_EMAIL =
    "UPDATE claude_auth_credentials SET "
    "  accessToken = ?, "
    "  refreshToken = ?, "
    "  expiresAt = ?, "
    "  refreshTokenExpiresAt = ?, "
    "  scopes = ?, "
    "  subscriptionType = ?, "
    "  rateLimitTier = ?, "
    "  accountUuid = ?, "
    "  emailAddress = ?, "
    "  organizationUuid = ?, "
    "  hasExtraUsageEnabled = ?, "
    "  billingType = ?, "
    "  accountCreatedAt = ?, "
    "  subscriptionCreatedAt = ?, "
    "  ccOnboardingFlags = ?, "
    "  claudeCodeTrialEndsAt = ?, "
    "  claudeCodeTrialDurationDays = ?, "
    "  seatTier = ?, "
    "  displayName = ?, "
    "  profileFetchedAt = ?, "
    "  organizationRole = ?, "
    "  workspaceRole = ?, "
    "  organizationName = ?, "
    "  organizationType = ?, "
    "  organizationRateLimitTier = ?, "
    "  userRateLimitTier = ? "
    "WHERE emailAddress = ?";

static const char *const SQL_GET_BY_EMAIL =
    "SELECT %s FROM claude_auth_credentials WHERE emailAddress = ?";

static const char *const SQL_CREATE_TABLE =
    "CREATE TABLE IF NOT EXISTS claude_auth_credentials ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  accessToken TEXT NOT NULL,"
    "  refreshToken TEXT NOT NULL,"
    "  expiresAt INTEGER,"
    "  refreshTokenExpiresAt INTEGER,"
    "  scopes TEXT NOT NULL,"
    "  subscriptionType TEXT NOT NULL,"
    "  rateLimitTier TEXT NOT NULL,"
    "  accountUuid TEXT NOT NULL,"
    "  emailAddress TEXT NOT NULL,"
    "  organizationUuid TEXT NOT NULL,"
    "  hasExtraUsageEnabled BOOL NOT NULL,"
    "  billingType TEXT NOT NULL,"
    "  accountCreatedAt TEXT NOT NULL,"
    "  subscriptionCreatedAt TEXT NOT NULL,"
    "  ccOnboardingFlags TEXT NOT NULL,"
    "  claudeCodeTrialEndsAt TEXT NULL,"
    "  claudeCodeTrialDurationDays TEXT NULL,"
    "  seatTier TEXT NULL,"
    "  displayName TEXT NOT NULL,"
    "  profileFetchedAt INTEGER NOT NULL,"
    "  organizationRole TEXT NOT NULL,"
    "  workspaceRole TEXT NULL,"
    "  organizationName TEXT NOT NULL,"
    "  organizationType TEXT NOT NULL,"
    "  organizationRateLimitTier TEXT NOT NULL,"
    "  userRateLimitTier TEXT NULL"
    ");";

static char *build_query_without_id(const char *tmpl) {
    int needed = snprintf(NULL, 0, tmpl, ALL_COLUMNS_WITHOUT_ID);
    if (needed < 0)
        return NULL;
    char *query = malloc((size_t)needed + 1);
    if (!query)
        return NULL;
    snprintf(query, (size_t)needed + 1, tmpl, ALL_COLUMNS_WITHOUT_ID);
    return query;
}

static char *build_query_all_columns(const char *tmpl) {
    int needed = snprintf(NULL, 0, tmpl, ALL_COLUMNS);
    if (needed < 0)
        return NULL;
    char *query = malloc((size_t)needed + 1);
    if (!query)
        return NULL;
    snprintf(query, (size_t)needed + 1, tmpl, ALL_COLUMNS);
    return query;
}

static void claude_to_stmt(ClaudeAiOauth *oauth, ClaudeOAuthAccount *account,
                           sqlite3_stmt *stmt) {
    int idx = 1;

    FIELDS_PRE_SCOPES(DO_BIND)

    {
        cJSON *scopes_arr = cJSON_CreateArray();
        for (size_t i = 0; i < oauth->scopes_count; i++) {
            cJSON_AddItemToArray(
                scopes_arr,
                cJSON_CreateString(oauth->scopes[i] ? oauth->scopes[i] : ""));
        }
        char *scopes_str = cJSON_PrintUnformatted(scopes_arr);
        sqlite3_bind_text(stmt, idx++, scopes_str ? scopes_str : "[]", -1,
                          SQLITE_TRANSIENT);
        free(scopes_str);
        cJSON_Delete(scopes_arr);
    }

    FIELDS_POST_SCOPES(DO_BIND)
}

static InternalAuth *sql_stmt_to_internal_auth(sqlite3_stmt *stmt) {
    InternalAuth *auth = malloc(sizeof(InternalAuth));
    if (!auth) {
        return NULL;
    }

    memset(auth, 0, sizeof(InternalAuth));

    int col = 0;

    auth->id = sqlite3_column_int64(stmt, col++);

    FIELDS_PRE_SCOPES(DO_READ)

    {
        const unsigned char *scopes_str = sqlite3_column_text(stmt, col++);
        if (scopes_str) {
            cJSON *arr = cJSON_Parse((const char *)scopes_str);
            if (arr && cJSON_IsArray(arr)) {
                auth->scopes_count = cJSON_GetArraySize(arr);
                auth->scopes = malloc(auth->scopes_count * sizeof(char *));
                if (auth->scopes) {
                    size_t i = 0;
                    cJSON *item;
                    cJSON_ArrayForEach(item, arr) {
                        auth->scopes[i] = cJSON_IsString(item)
                                              ? dup_str(item->valuestring)
                                              : NULL;
                        i++;
                    }
                } else {
                    auth->scopes_count = 0;
                }
                cJSON_Delete(arr);
            } else {
                cJSON_Delete(arr);
                char *copy = dup_str((const char *)scopes_str);
                if (copy) {
                    auth->scopes = str_split(copy, ',', &auth->scopes_count);
                    free(copy);
                }
            }
        }
    }

    FIELDS_POST_SCOPES(DO_READ)

    return auth;
}

void free_internal_auth(InternalAuth *auth) {
    FIELDS_PRE_SCOPES(DO_FREE)
    FIELDS_POST_SCOPES(DO_FREE)

    for (size_t i = 0; i < auth->scopes_count; i++)
        free(auth->scopes[i]);
    free(auth->scopes);
}

static sqlite3 *get_db(void) {
    char *path = append_to_home("van/claude.db");
    if (!path) {
        return NULL;
    }

    char *last_slash = strrchr(path, '/');
    if (last_slash && last_slash != path) {
        *last_slash = '\0';

        if (is_file(path)) {
            if (remove(path) != 0) {
                *last_slash = '/';
                free(path);
                return NULL;
            }
        }
        if (!is_dir(path)) {
            if (mkdir_p(path, 0755) != 0) {
                *last_slash = '/';
                free(path);
                return NULL;
            }
        }

        *last_slash = '/';
    }

    sqlite3 *db;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        free(path);
        return NULL;
    }

    if (sqlite3_exec(db, SQL_CREATE_TABLE, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(path);
        return NULL;
    }

    free(path);
    return db;
}

static size_t auth_credentials_count(sqlite3 *db) {
    sqlite3_stmt *count_stmt;
    const char *sql = "SELECT COUNT(*) FROM claude_auth_credentials";
    if (sqlite3_prepare_v2(db, sql, -1, &count_stmt, NULL) != SQLITE_OK) {
        return 0;
    }

    size_t count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        count = (size_t)sqlite3_column_int64(count_stmt, 0);
    }

    sqlite3_finalize(count_stmt);
    return count;
}

uint32_t delete_auth(uint64_t id) {
    sqlite3 *db = get_db();
    if (db == NULL) {
        return 0;
    }

    const char *sql = "DELETE FROM claude_auth_credentials WHERE id = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return (rc == SQLITE_DONE && changes > 0) ? 1 : 0;
}

InternalAuth **get_all_claude_oauth_configs(size_t *out_size) {
    *out_size = 0;

    sqlite3 *db = get_db();
    if (db == NULL) {
        return NULL;
    }

    size_t count = auth_credentials_count(db);
    if (count == 0) {
        sqlite3_close(db);
        return malloc(sizeof(InternalAuth *));
    }

    InternalAuth **result = malloc(count * sizeof(InternalAuth *));
    if (!result) {
        sqlite3_close(db);
        return NULL;
    }

    char *query = build_query_all_columns(SQL_GET_ALL);
    if (!query) {
        fprintf(stderr, "failed to build query\n");
        return NULL;
    }
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        free(query);
        free(result);
        sqlite3_close(db);
        return NULL;
    }
    free(query);

    size_t idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        InternalAuth *auth = sql_stmt_to_internal_auth(stmt);
        if (!auth) {
            goto cleanup;
        }

        result[idx++] = auth;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    *out_size = idx;
    return result;

cleanup:
    for (size_t i = 0; i < idx; i++) {
        free_internal_auth(result[i]);
        free(result[i]);
    }
    free(result);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return NULL;
}

uint64_t insert_auth(ClaudeAiOauth auth, ClaudeOAuthAccount account) {
    sqlite3 *db = get_db();
    if (db == NULL) {
        return 0;
    }

    char *query = build_query_without_id(SQL_INSERT);
    if (!query) {
        fprintf(stderr, "failed to build query\n");
        return 0;
    }
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(query);
        return 0;
    }
    free(query);

    claude_to_stmt(&auth, &account, stmt);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }
    sqlite3_finalize(stmt);

    sqlite3_int64 id = sqlite3_last_insert_rowid(db);
    sqlite3_close(db);
    return (uint64_t)id;
}

InternalAuth *get_auth_by_id(uint64_t id) {
    sqlite3 *db = get_db();
    if (db == NULL) {
        fprintf(stderr, "failed to get database\n");
        return NULL;
    }

    char *query = build_query_all_columns(SQL_GET_BY_ID);
    if (!query) {
        fprintf(stderr, "failed to build query\n");
        return NULL;
    }
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(query);
        return NULL;
    }
    free(query);

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);

    InternalAuth *auth = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auth = sql_stmt_to_internal_auth(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return auth;
}

InternalAuth *get_auth_by_email(char *email) {
    if (!email)
        return NULL;

    sqlite3 *db = get_db();
    if (db == NULL) {
        fprintf(stderr, "failed to get database\n");
        return NULL;
    }

    char *query = build_query_all_columns(SQL_GET_BY_EMAIL);
    if (!query) {
        fprintf(stderr, "failed to build query\n");
        return NULL;
    }
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(query);
        return NULL;
    }
    free(query);

    sqlite3_bind_text(stmt, 1, email, -1, SQLITE_TRANSIENT);

    InternalAuth *auth = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auth = sql_stmt_to_internal_auth(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return auth;
}

uint32_t update_auth_by_email(ClaudeAiOauth auth, ClaudeOAuthAccount account,
                              const char *email) {
    if (!email)
        return 0;
    sqlite3 *db = get_db();
    if (db == NULL)
        return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, SQL_UPDATE_BY_EMAIL, -1, &stmt, NULL) !=
        SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    claude_to_stmt(&auth, &account, stmt);
    sqlite3_bind_text(stmt, 27, email, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return (rc == SQLITE_DONE && changes > 0) ? 1 : 0;
}
