#include "claude.h"
#include "db.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COL_WIDTH 40

static size_t safe_len(const char *s) { return s ? strlen(s) : 0; }

static int int64_len(int64_t val) {
    char buf[32];
    return snprintf(buf, sizeof(buf), "%lld", (long long)val);
}

static void print_col(const char *s, size_t width) {
    if (!s)
        s = "";

    size_t len = strlen(s);

    if (len > width) {
        if (width <= 3) {
            for (size_t i = 0; i < width; i++)
                putchar('.');
            return;
        }
        fwrite(s, 1, width - 3, stdout);
        fputs("...", stdout);
    } else {
        printf("%-*s", (int)width, s);
    }
}

int run_list(ClaudeCredentials *current_cred) {
    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
        free_claude_credentials(current_cred);
        return 1;
    }

    size_t w_id = strlen("ID");
    size_t w_name = strlen("Name");
    size_t w_token = strlen("Access Token");
    size_t w_refresh = strlen("Refresh Token");
    size_t w_exp = strlen("Expires");

    for (size_t i = 0; i < auth_len; i++) {
        char id_buf[32];
        size_t id_len = (size_t)snprintf(id_buf, sizeof(id_buf), "%lld",
                                          (long long)auths[i]->id);
        if (id_len > w_id)
            w_id = id_len;

        if (safe_len(auths[i]->name) > w_name)
            w_name = safe_len(auths[i]->name);
        if (safe_len(auths[i]->accessToken) > w_token)
            w_token = safe_len(auths[i]->accessToken);
        if (safe_len(auths[i]->refreshToken) > w_refresh)
            w_refresh = safe_len(auths[i]->refreshToken);
        if ((size_t)int64_len(auths[i]->expiresAt) > w_exp)
            w_exp = (size_t)int64_len(auths[i]->expiresAt);
    }

    if (w_token > MAX_COL_WIDTH)
        w_token = MAX_COL_WIDTH;
    if (w_refresh > MAX_COL_WIDTH)
        w_refresh = MAX_COL_WIDTH;

    print_col("ID", w_id);
    printf("  ");
    print_col("Name", w_name);
    printf("  ");
    print_col("Access Token", w_token);
    printf("  ");
    print_col("Refresh Token", w_refresh);
    printf("  ");
    print_col("Expires", w_exp);
    printf("\n");

    for (size_t i = 0; i < w_id; i++)
        putchar('-');
    printf("  ");
    for (size_t i = 0; i < w_token; i++)
        putchar('-');
    printf("  ");
    for (size_t i = 0; i < w_refresh; i++)
        putchar('-');
    printf("  ");
    for (size_t i = 0; i < w_exp; i++)
        putchar('-');
    printf("\n");

    for (size_t i = 0; i < auth_len; i++) {
        char id_buf[32];
        snprintf(id_buf, sizeof(id_buf), "%lld", (long long)auths[i]->id);
        print_col(id_buf, w_id);
        printf("  ");

        print_col(auths[i]->name ? auths[i]->name : "(none)", w_name);
        printf("  ");

        print_col(auths[i]->accessToken ? auths[i]->accessToken : "(none)",
                  w_token);
        printf("  ");
        print_col(auths[i]->refreshToken ? auths[i]->refreshToken : "(none)",
                  w_refresh);
        printf("  ");

        char exp_buf[32];
        snprintf(exp_buf, sizeof(exp_buf), "%lld",
                 (long long)auths[i]->expiresAt);
        print_col(exp_buf, w_exp);
        printf("\n");
    }

    printf("\n%zu credential(s)\n", auth_len);

    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 0;
}

int run_add(ClaudeCredentials *current_cred) {
    bool should_add =
        prompt_yes_no("Do you want to add the current claude code "
                      "account to your credentials database?");
    if (should_add) {
        char *name = prompt("Please add a name for this config: ");

        uint64_t id = insert_auth(current_cred->claudeAiOauth, name);
        if (id == 0) {
            printf("failed to add new claude credentials");
            free(name);
            return -1;
        }

        printf("inserted id: %llu\n", (unsigned long long)id);
        free(name);
    }

    free_claude_credentials(current_cred);
    return 0;
}

int run_delete(ClaudeCredentials *current_cred) {
    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
        free_claude_credentials(current_cred);
        return 1;
    }

    printf("Delete one of the following credentials:\n\n");

    for (size_t i = 0; i < auth_len; i++) {
        printf("%lld - %s\n", (long long)auths[i]->id,
               auths[i]->name ? auths[i]->name : "(none)");
    }

    printf("\n");

    char *id = prompt("ID to delete: ");
    if (!id) {
        fprintf(stderr, "The ID you provided is not valid.\n");
        goto cleanup_fail;
    }

    errno = 0;
    char *end;
    unsigned long long val = strtoull(id, &end, 10);

    if (errno == ERANGE) {
        fprintf(stderr, "The ID you provided is out of range.\n");
        goto cleanup_fail;
    }
    if (end == id) {
        fprintf(stderr, "The ID you provided has to be numerical.\n");
        goto cleanup_fail;
    }
    if (*end != '\0') {
        fprintf(stderr, "The ID you provided has trailing garbage.\n");
        goto cleanup_fail;
    }

    if (delete_auth((uint64_t)val) == 0) {
        fprintf(stderr, "Failed to delete database entry.\n");
        goto cleanup_fail;
    }

    printf("Deleted credential with ID %llu.\n", (unsigned long long)val);
    free(id);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 0;

cleanup_fail:
    free(id);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 1;
}

int run_show(ClaudeCredentials *current_cred) {
    free_claude_credentials(current_cred);
    return 0;
}

int run_rename(ClaudeCredentials *current_cred) {
    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
        free_claude_credentials(current_cred);
        return 1;
    }

    printf("Rename one of the following credentials:\n\n");

    for (size_t i = 0; i < auth_len; i++) {
        printf("%lld - %s\n", (long long)auths[i]->id,
               auths[i]->name ? auths[i]->name : "(none)");
    }

    printf("\n");

    char *id = prompt("ID to rename: ");
    if (!id) {
        fprintf(stderr, "The ID you provided is not valid.\n");
        goto cleanup_fail;
    }

    errno = 0;
    char *end;
    unsigned long long val = strtoull(id, &end, 10);

    if (errno == ERANGE) {
        fprintf(stderr, "The ID you provided is out of range.\n");
        goto cleanup_fail;
    }
    if (end == id) {
        fprintf(stderr, "The ID you provided has to be numerical.\n");
        goto cleanup_fail;
    }
    if (*end != '\0') {
        fprintf(stderr, "The ID you provided has trailing garbage.\n");
        goto cleanup_fail;
    }

    char *newName = prompt("Please type in a new name: ");

    if (rename_auth((uint64_t)val, newName) == 0) {
        fprintf(stderr, "Failed to rename database entry.\n");
        free(newName);
        goto cleanup_fail;
    }

    printf("Credential %llu renamed to %s.\n", (unsigned long long)val,
           newName);

    free(id);
    free(newName);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 0;

cleanup_fail:
    free(id);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 1;
}

int run_swap(ClaudeCredentials *current_cred, char *path) {
    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
        free_claude_credentials(current_cred);
        free(path);
        return 1;
    }

    printf("Swap your current config with one of the following:\n\n");

    for (size_t i = 0; i < auth_len; i++) {
        printf("%lld - %s\n", (long long)auths[i]->id,
               auths[i]->name ? auths[i]->name : "(none)");
    }

    printf("\n");

    char *id = prompt("ID to swap with: ");
    if (!id) {
        fprintf(stderr, "The ID you provided is not valid.\n");
        goto cleanup_fail;
    }

    errno = 0;
    char *end;
    unsigned long long val = strtoull(id, &end, 10);

    if (errno == ERANGE) {
        fprintf(stderr, "The ID you provided is out of range.\n");
        goto cleanup_fail;
    }
    if (end == id) {
        fprintf(stderr, "The ID you provided has to be numerical.\n");
        goto cleanup_fail;
    }
    if (*end != '\0') {
        fprintf(stderr, "The ID you provided has trailing garbage.\n");
        goto cleanup_fail;
    }

    InternalAuth *internal_auth = get_auth_by_id((uint64_t)val);
    if (!internal_auth) {
        fprintf(stderr, "Failed to find the selected credentials.\n");
        goto cleanup_fail;
    }

    ClaudeCredentials new_cred = {0};
    new_cred.claudeAiOauth.accessToken = dup_str(internal_auth->accessToken);
    new_cred.claudeAiOauth.refreshToken = dup_str(internal_auth->refreshToken);
    new_cred.claudeAiOauth.expiresAt = internal_auth->expiresAt;
    new_cred.claudeAiOauth.refreshTokenExpiresAt =
        internal_auth->refreshTokenExpiresAt;
    new_cred.claudeAiOauth.subscriptionType =
        dup_str(internal_auth->subscriptionType);
    new_cred.claudeAiOauth.rateLimitTier =
        dup_str(internal_auth->rateLimitTier);

    if (internal_auth->scopes && internal_auth->scopes_count > 0) {
        new_cred.claudeAiOauth.scopes =
            malloc(internal_auth->scopes_count * sizeof(char *));
        if (new_cred.claudeAiOauth.scopes) {
            new_cred.claudeAiOauth.scopes_count = internal_auth->scopes_count;
            for (size_t i = 0; i < internal_auth->scopes_count; i++) {
                new_cred.claudeAiOauth.scopes[i] =
                    dup_str(internal_auth->scopes[i]);
            }
        }
    }

    new_cred.mcpOAuth = current_cred->mcpOAuth;

    int rc = write_config_to_file(&new_cred, path);

    free(new_cred.claudeAiOauth.accessToken);
    free(new_cred.claudeAiOauth.refreshToken);
    free(new_cred.claudeAiOauth.subscriptionType);
    free(new_cred.claudeAiOauth.rateLimitTier);
    for (size_t i = 0; i < new_cred.claudeAiOauth.scopes_count; i++)
        free(new_cred.claudeAiOauth.scopes[i]);
    free(new_cred.claudeAiOauth.scopes);

    free_internal_auth(internal_auth);
    free(internal_auth);

    if (rc != 0) {
        fprintf(stderr, "Failed to write config to file.\n");
        goto cleanup_fail;
    }

    printf("Swapped config successfully.\n");

    free(id);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    free(path);
    return 0;

cleanup_fail:
    free(id);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    free(path);
    return 1;
}
