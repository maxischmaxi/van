#include "db.h"
#include "claude.h"
#include "sqlite3.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void claude_to_stmt(ClaudeAiOauth *auth, ClaudeOAuthAccount *account,
                           sqlite3_stmt *stmt) {
    char *scopes = str_array_to_str(auth->scopes, auth->scopes_count, ",");

    sqlite3_bind_text(stmt, 1, auth->accessToken, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, auth->refreshToken, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, auth->expiresAt);
    sqlite3_bind_int64(stmt, 4, auth->refreshTokenExpiresAt);
    sqlite3_bind_text(stmt, 5, scopes ? scopes : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, auth->subscriptionType, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, auth->rateLimitTier, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, account->accountUuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, account->emailAddress, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, account->organizationUuid, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 11, account->hasExtraUsageEnabled == false ? 0 : 1);
    sqlite3_bind_text(stmt, 12, account->billingType, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, account->accountCreatedAt, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, account->subscriptionCreatedAt, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 15, account->ccOnboardingFlags, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 16, account->claudeCodeTrialEndsAt, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 17, account->claudeCodeTrialDurationDays, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 18, account->seatTier, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 19, account->displayName, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 20, account->profileFetchedAt);
    sqlite3_bind_text(stmt, 21, account->organizationRole, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 22, account->workspaceRole, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 23, account->organizationName, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 24, account->organizationType, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 25, account->organizationRateLimitTier, -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 26, account->userRateLimitTier, -1,
                      SQLITE_TRANSIENT);

    free(scopes);
}

static InternalAuth *sql_stmt_to_internal_auth(sqlite3_stmt *stmt) {
    InternalAuth *auth = malloc(sizeof(InternalAuth));
    if (!auth) {
        return NULL;
    }

    memset(auth, 0, sizeof(InternalAuth));

    auth->id = sqlite3_column_int64(stmt, 0);
    auth->accessToken = dup_str((const char *)sqlite3_column_text(stmt, 1));
    auth->refreshToken = dup_str((const char *)sqlite3_column_text(stmt, 2));
    auth->expiresAt = sqlite3_column_int64(stmt, 3);
    auth->refreshTokenExpiresAt = sqlite3_column_int64(stmt, 4);
    auth->subscriptionType =
        dup_str((const char *)sqlite3_column_text(stmt, 6));
    auth->rateLimitTier = dup_str((const char *)sqlite3_column_text(stmt, 7));
    auth->accountUuid = dup_str((const char *)sqlite3_column_text(stmt, 8));
    auth->emailAddress = dup_str((const char *)sqlite3_column_text(stmt, 9));
    auth->organizationUuid =
        dup_str((const char *)sqlite3_column_text(stmt, 10));
    auth->hasExtraUsageEnabled = sqlite3_column_int(stmt, 11) != 0;
    auth->billingType = dup_str((const char *)sqlite3_column_text(stmt, 12));
    auth->accountCreatedAt =
        dup_str((const char *)sqlite3_column_text(stmt, 13));
    auth->subscriptionCreatedAt =
        dup_str((const char *)sqlite3_column_text(stmt, 14));
    auth->ccOnboardingFlags =
        dup_str((const char *)sqlite3_column_text(stmt, 15));
    auth->claudeCodeTrialEndsAt =
        dup_str((const char *)sqlite3_column_text(stmt, 16));
    auth->claudeCodeTrialDurationDays =
        dup_str((const char *)sqlite3_column_text(stmt, 17));
    auth->seatTier = dup_str((const char *)sqlite3_column_text(stmt, 18));
    auth->displayName = dup_str((const char *)sqlite3_column_text(stmt, 19));
    auth->profileFetchedAt = sqlite3_column_int64(stmt, 20);
    auth->organizationRole =
        dup_str((const char *)sqlite3_column_text(stmt, 21));
    auth->workspaceRole = dup_str((const char *)sqlite3_column_text(stmt, 22));
    auth->organizationName =
        dup_str((const char *)sqlite3_column_text(stmt, 23));
    auth->organizationType =
        dup_str((const char *)sqlite3_column_text(stmt, 24));
    auth->organizationRateLimitTier =
        dup_str((const char *)sqlite3_column_text(stmt, 25));
    auth->userRateLimitTier =
        dup_str((const char *)sqlite3_column_text(stmt, 26));

    const unsigned char *scopes_str = sqlite3_column_text(stmt, 5);

    if (scopes_str) {
        char *scopes_copy = dup_str((const char *)scopes_str);
        if (scopes_copy) {
            auth->scopes = str_split(scopes_copy, ',', &auth->scopes_count);
            free(scopes_copy);
        }
    }

    return auth;
}

void free_internal_auth(InternalAuth *auth) {
    free(auth->accessToken);
    free(auth->refreshToken);
    free(auth->subscriptionType);
    free(auth->rateLimitTier);
    for (size_t i = 0; i < auth->scopes_count; i++)
        free(auth->scopes[i]);
    free(auth->scopes);

    free(auth->accountUuid);
    free(auth->emailAddress);
    free(auth->organizationUuid);
    free(auth->billingType);
    free(auth->accountCreatedAt);
    free(auth->subscriptionCreatedAt);
    free(auth->ccOnboardingFlags);
    free(auth->claudeCodeTrialEndsAt);
    free(auth->claudeCodeTrialDurationDays);
    free(auth->seatTier);
    free(auth->displayName);
    free(auth->organizationRole);
    free(auth->workspaceRole);
    free(auth->organizationName);
    free(auth->organizationType);
    free(auth->organizationRateLimitTier);
    free(auth->userRateLimitTier);
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
