#include "claude.h"
#include "db.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_COL_WIDTH 40

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

int run_list(void) {
    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
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

        if (safe_len(auths[i]->emailAddress) > w_name)
            w_name = safe_len(auths[i]->emailAddress);
        if (safe_len(auths[i]->accessToken) > w_token)
            w_token = safe_len(auths[i]->accessToken);
        if (safe_len(auths[i]->refreshToken) > w_refresh)
            w_refresh = safe_len(auths[i]->refreshToken);
        if ((size_t)safe_len("2026-01-01 00:00") > w_exp)
            w_exp = (size_t)safe_len("2026-01-01 00:00");
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

        print_col(auths[i]->emailAddress ? auths[i]->emailAddress : "(none)",
                  w_name);
        printf("  ");

        print_col(auths[i]->accessToken ? auths[i]->accessToken : "(none)",
                  w_token);
        printf("  ");
        print_col(auths[i]->refreshToken ? auths[i]->refreshToken : "(none)",
                  w_refresh);
        printf("  ");

        char exp_buf[32];
        ms_to_timestamp(auths[i]->expiresAt, exp_buf, sizeof(exp_buf));
        print_col(exp_buf, w_exp);
        printf("\n");
    }

    printf("\n%zu credential(s)\n", auth_len);

    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 0;
}

int run_add(ClaudeCredentials *current_cred) {
    char *email = fetch_account_email(current_cred->claudeAiOauth.accessToken);
    if (!email) {
        printf("could not fetch account email\n");
        return -1;
    }

    int needed = snprintf(NULL, 0,
                          "Do you want to add the current claude code account "
                          "with email \"%s\" to your credentials database?",
                          email);
    char *add_prompt = malloc(needed + 1);
    if (!add_prompt) {
        printf("failed to allocate prompt string\n");
        free(email);
        return -1;
    }
    snprintf(add_prompt, needed + 1,
             "Do you want to add the current claude code account with email "
             "\"%s\" to your credentials database?",
             email);

    bool should_add = prompt_yes_no(add_prompt);
    free(add_prompt);

    if (should_add) {
        InternalAuth *existing_auth = get_auth_by_email(email);

        if (existing_auth) {
            free_internal_auth(existing_auth);
            free(existing_auth);
            bool should_overwrite =
                prompt_yes_no("Account with this email already exists. do you "
                              "want to overwrite it?");

            if (should_overwrite) {
                uint64_t id = insert_auth(current_cred->claudeAiOauth,
                                          current_cred->account);
                if (id == 0) {
                    printf("failed to add new claude credentials\n");
                    free(email);
                    return -1;
                }
                printf("inserted id: %llu\n", (unsigned long long)id);
            }

            printf("nothing done\n");
            free(email);
            return 0;
        }

        uint64_t id =
            insert_auth(current_cred->claudeAiOauth, current_cred->account);
        if (id == 0) {
            printf("failed to add new claude credentials\n");
            free(email);
            return -1;
        }
    }

    free(email);
    return 0;
}

int run_delete(void) {
    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
        return 1;
    }

    printf("Delete one of the following credentials:\n\n");

    for (size_t i = 0; i < auth_len; i++) {
        printf("%lld - %s\n", (long long)auths[i]->id,
               auths[i]->emailAddress ? auths[i]->emailAddress : "(none)");
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
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 0;

cleanup_fail:
    free(id);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    return 1;
}

int run_show(ClaudeCredentials *current_cred) {
    printf("Subscription: %s\n",
           current_cred->claudeAiOauth.subscriptionType
               ? current_cred->claudeAiOauth.subscriptionType
               : "(none)");
    printf("Rate limit: %s\n", current_cred->claudeAiOauth.rateLimitTier
                                   ? current_cred->claudeAiOauth.rateLimitTier
                                   : "(none)");

    char *email = fetch_account_email(current_cred->claudeAiOauth.accessToken);
    if (email) {
        printf("Logged in as: %s\n", email);
        free(email);
    } else {
        printf("Failed to fetch account info.\n");
    }

    return 0;
}

int run_swap(ClaudeCredentials *current_cred) {
    char *credentials_path = append_to_home(".claude/.credentials.json");
    if (credentials_path == NULL) {
        printf("failed to load credentials\n");
        return 1;
    }

    char *claude_path = append_to_home(".claude.json");
    if (claude_path == NULL) {
        printf("failed to load credentials\n");
        free(credentials_path);
        return 1;
    }

    InternalAuth **auths = NULL;
    size_t auth_len = 0;
    auths = get_all_claude_oauth_configs(&auth_len);
    if (!auths) {
        printf("failed to load credentials\n");
        free(credentials_path);
        free(claude_path);
        return 1;
    }

    printf("Swap your current config with one of the following:\n\n");

    for (size_t i = 0; i < auth_len; i++) {
        printf("%lld - %s\n", (long long)auths[i]->id,
               auths[i]->emailAddress ? auths[i]->emailAddress : "(none)");
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

    new_cred.account.accountUuid = dup_str(internal_auth->accountUuid);
    new_cred.account.emailAddress = dup_str(internal_auth->emailAddress);
    new_cred.account.organizationUuid =
        dup_str(internal_auth->organizationUuid);
    new_cred.account.hasExtraUsageEnabled =
        internal_auth->hasExtraUsageEnabled;
    new_cred.account.billingType = dup_str(internal_auth->billingType);
    new_cred.account.accountCreatedAt =
        dup_str(internal_auth->accountCreatedAt);
    new_cred.account.subscriptionCreatedAt =
        dup_str(internal_auth->subscriptionCreatedAt);
    new_cred.account.ccOnboardingFlags =
        dup_str(internal_auth->ccOnboardingFlags);
    new_cred.account.claudeCodeTrialEndsAt =
        dup_str(internal_auth->claudeCodeTrialEndsAt);
    new_cred.account.claudeCodeTrialDurationDays =
        dup_str(internal_auth->claudeCodeTrialDurationDays);
    new_cred.account.seatTier = dup_str(internal_auth->seatTier);
    new_cred.account.displayName = dup_str(internal_auth->displayName);
    new_cred.account.profileFetchedAt = internal_auth->profileFetchedAt;
    new_cred.account.organizationRole =
        dup_str(internal_auth->organizationRole);
    new_cred.account.workspaceRole = dup_str(internal_auth->workspaceRole);
    new_cred.account.organizationName =
        dup_str(internal_auth->organizationName);
    new_cred.account.organizationType =
        dup_str(internal_auth->organizationType);
    new_cred.account.organizationRateLimitTier =
        dup_str(internal_auth->organizationRateLimitTier);
    new_cred.account.userRateLimitTier =
        dup_str(internal_auth->userRateLimitTier);

    int rc = write_config_to_file(&new_cred, credentials_path);
    int rc2 = 0;
    if (rc == 0) {
        rc2 = write_account_to_file(&new_cred.account, claude_path);
    }

    free(new_cred.claudeAiOauth.accessToken);
    free(new_cred.claudeAiOauth.refreshToken);
    free(new_cred.claudeAiOauth.subscriptionType);
    free(new_cred.claudeAiOauth.rateLimitTier);
    for (size_t i = 0; i < new_cred.claudeAiOauth.scopes_count; i++)
        free(new_cred.claudeAiOauth.scopes[i]);
    free(new_cred.claudeAiOauth.scopes);
    free_claude_oauth_account(&new_cred.account);

    free_internal_auth(internal_auth);
    free(internal_auth);

    if (rc != 0) {
        fprintf(stderr, "Failed to write credentials to file.\n");
        goto cleanup_fail;
    }
    if (rc2 != 0) {
        fprintf(stderr, "Failed to write account info to file.\n");
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
    free(credentials_path);
    free(claude_path);
    return 0;

cleanup_fail:
    free(id);
    free_claude_credentials(current_cred);
    for (size_t i = 0; i < auth_len; i++) {
        free_internal_auth(auths[i]);
        free(auths[i]);
    }
    free(auths);
    free(credentials_path);
    free(claude_path);
    return 1;
}
