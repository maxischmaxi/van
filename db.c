#include "db.h"
#include "claude.h"
#include "sqlite3.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void free_internal_auth(InternalAuth *auth) {
    free(auth->accessToken);
    free(auth->refreshToken);
    free(auth->subscriptionType);
    free(auth->rateLimitTier);
    for (size_t i = 0; i < auth->scopes_count; i++)
        free(auth->scopes[i]);
    free(auth->scopes);
    free(auth->name);
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

    const char *sql = "CREATE TABLE IF NOT EXISTS claude_auth_credentials ("
                      "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "  name TEXT NOT NULL,"
                      "  access_token TEXT NOT NULL,"
                      "  refresh_token TEXT NOT NULL,"
                      "  expires_at INTEGER,"
                      "  refresh_token_expires_at INTEGER,"
                      "  scopes TEXT NOT NULL,"
                      "  subscription_type TEXT NOT NULL,"
                      "  rate_limit_tier TEXT NOT NULL"
                      ");";

    if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
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

    const char *sql =
        "SELECT id, name, access_token, refresh_token, "
        "expires_at, refresh_token_expires_at, scopes, "
        "subscription_type, rate_limit_tier FROM claude_auth_credentials";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        free(result);
        sqlite3_close(db);
        return NULL;
    }

    size_t idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        InternalAuth *auth = malloc(sizeof(InternalAuth));
        if (!auth)
            goto cleanup;

        memset(auth, 0, sizeof(InternalAuth));

        auth->id = sqlite3_column_int64(stmt, 0);
        auth->name = dup_str((const char *)sqlite3_column_text(stmt, 1));
        auth->accessToken = dup_str((const char *)sqlite3_column_text(stmt, 2));
        auth->refreshToken =
            dup_str((const char *)sqlite3_column_text(stmt, 3));
        auth->expiresAt = sqlite3_column_int64(stmt, 4);
        auth->refreshTokenExpiresAt = sqlite3_column_int64(stmt, 5);
        auth->subscriptionType =
            dup_str((const char *)sqlite3_column_text(stmt, 7));
        auth->rateLimitTier =
            dup_str((const char *)sqlite3_column_text(stmt, 8));

        const unsigned char *scopes_str = sqlite3_column_text(stmt, 6);

        if (scopes_str) {
            char *scopes_copy = dup_str((const char *)scopes_str);
            if (scopes_copy) {
                auth->scopes = str_split(scopes_copy, ',', &auth->scopes_count);
                free(scopes_copy);
            }
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

uint64_t insert_auth(ClaudeAiOauth auth, char *name) {
    sqlite3 *db = get_db();
    if (db == NULL) {
        return 0;
    }

    const char *sql = "INSERT INTO claude_auth_credentials ("
                      "name, access_token, refresh_token,"
                      "expires_at, refresh_token_expires_at, scopes, "
                      "subscription_type, rate_limit_tier "
                      ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    char *scopes = str_array_to_str(auth.scopes, auth.scopes_count, ",");

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, auth.accessToken, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, auth.refreshToken, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, auth.expiresAt);
    sqlite3_bind_int64(stmt, 5, auth.refreshTokenExpiresAt);
    sqlite3_bind_text(stmt, 6, scopes ? scopes : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, auth.subscriptionType, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, auth.rateLimitTier, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        free(scopes);
        sqlite3_close(db);
        return 0;
    }
    sqlite3_finalize(stmt);

    sqlite3_int64 id = sqlite3_last_insert_rowid(db);
    free(scopes);
    sqlite3_close(db);
    return (uint64_t)id;
}

uint32_t rename_auth(uint64_t id, char *name) {
    sqlite3 *db = get_db();
    if (db == NULL) {
        fprintf(stderr, "failed to get database\n");
        return 0;
    }

    const char *sql = "UPDATE claude_auth_credentials SET "
                      "name = ? WHERE id = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        fprintf(stderr, "failed to prepare sql statement\n");
        return 0;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)id);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (rc != SQLITE_DONE || changes == 0) {
        return 0;
    }

    return (uint64_t)id;
}

InternalAuth *get_auth_by_id(uint64_t id) {
    sqlite3 *db = get_db();
    if (db == NULL) {
        fprintf(stderr, "failed to get database\n");
        return NULL;
    }

    const char *sql = "SELECT id, name, access_token, refresh_token, "
                      "expires_at, refresh_token_expires_at, scopes, "
                      "subscription_type, rate_limit_tier "
                      "FROM claude_auth_credentials WHERE id = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);

    InternalAuth *auth = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auth = malloc(sizeof(InternalAuth));
        if (!auth) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return NULL;
        }
        memset(auth, 0, sizeof(InternalAuth));

        auth->id = sqlite3_column_int64(stmt, 0);
        auth->expiresAt = sqlite3_column_int64(stmt, 4);
        auth->refreshTokenExpiresAt = sqlite3_column_int64(stmt, 5);
        auth->name = dup_str((const char *)sqlite3_column_text(stmt, 1));
        auth->accessToken = dup_str((const char *)sqlite3_column_text(stmt, 2));
        auth->refreshToken =
            dup_str((const char *)sqlite3_column_text(stmt, 3));
        auth->subscriptionType =
            dup_str((const char *)sqlite3_column_text(stmt, 7));
        auth->rateLimitTier =
            dup_str((const char *)sqlite3_column_text(stmt, 8));

        const unsigned char *scopes_str = sqlite3_column_text(stmt, 6);
        if (scopes_str) {
            char *scopes_copy = dup_str((const char *)scopes_str);
            if (scopes_copy) {
                auth->scopes = str_split(scopes_copy, ',', &auth->scopes_count);
                free(scopes_copy);
            }
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return auth;
}

InternalAuth *get_auth_by_name(char *name) {
    if (!name)
        return NULL;

    sqlite3 *db = get_db();
    if (db == NULL) {
        fprintf(stderr, "failed to get database\n");
        return NULL;
    }

    const char *sql = "SELECT id, name, access_token, refresh_token, "
                      "expires_at, refresh_token_expires_at, scopes, "
                      "subscription_type, rate_limit_tier "
                      "FROM claude_auth_credentials WHERE name = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);

    InternalAuth *auth = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auth = malloc(sizeof(InternalAuth));
        if (!auth) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return NULL;
        }
        memset(auth, 0, sizeof(InternalAuth));

        auth->id = sqlite3_column_int64(stmt, 0);
        auth->expiresAt = sqlite3_column_int64(stmt, 4);
        auth->refreshTokenExpiresAt = sqlite3_column_int64(stmt, 5);
        auth->name = dup_str((const char *)sqlite3_column_text(stmt, 1));
        auth->accessToken = dup_str((const char *)sqlite3_column_text(stmt, 2));
        auth->refreshToken =
            dup_str((const char *)sqlite3_column_text(stmt, 3));
        auth->subscriptionType =
            dup_str((const char *)sqlite3_column_text(stmt, 7));
        auth->rateLimitTier =
            dup_str((const char *)sqlite3_column_text(stmt, 8));

        const unsigned char *scopes_str = sqlite3_column_text(stmt, 6);
        if (scopes_str) {
            char *scopes_copy = dup_str((const char *)scopes_str);
            if (scopes_copy) {
                auth->scopes = str_split(scopes_copy, ',', &auth->scopes_count);
                free(scopes_copy);
            }
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return auth;
}
