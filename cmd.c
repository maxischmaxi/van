#include "claude.h"
#include "db.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_COL_WIDTH 40

static void cleanup_free(void *p) { free(*(void **)p); }

#define AUTO_FREE __attribute__((cleanup(cleanup_free)))

typedef struct {
    InternalAuth **items;
    size_t count;
} AuthList;

static void cleanup_auth_list(void *p) {
    AuthList *a = (AuthList *)p;
    for (size_t i = 0; i < a->count; i++) {
        free_internal_auth(a->items[i]);
        free(a->items[i]);
    }
    free(a->items);
}

static void cleanup_internal_auth(void *p) {
    InternalAuth *a = *(InternalAuth **)p;
    if (a) {
        free_internal_auth(a);
        free(a);
    }
}

#define AUTO_AUTH_LIST __attribute__((cleanup(cleanup_auth_list)))
#define AUTO_INTERNAL_AUTH __attribute__((cleanup(cleanup_internal_auth)))

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
    (void)current_cred;

    AUTO_AUTH_LIST AuthList auths = {0};
    auths.items = get_all_claude_oauth_configs(&auths.count);
    if (!auths.items) {
        LOG_ERR("failed to load credentials");
        return 1;
    }

    size_t w_id = strlen("ID");
    size_t w_name = strlen("Name");
    size_t w_token = strlen("Access Token");
    size_t w_refresh = strlen("Refresh Token");
    size_t w_exp = strlen("Expires");

    for (size_t i = 0; i < auths.count; i++) {
        char id_buf[32];
        size_t id_len = (size_t)snprintf(id_buf, sizeof(id_buf), "%lld",
                                         (long long)auths.items[i]->id);
        if (id_len > w_id)
            w_id = id_len;

        if (safe_len(auths.items[i]->emailAddress) > w_name)
            w_name = safe_len(auths.items[i]->emailAddress);
        if (safe_len(auths.items[i]->accessToken) > w_token)
            w_token = safe_len(auths.items[i]->accessToken);
        if (safe_len(auths.items[i]->refreshToken) > w_refresh)
            w_refresh = safe_len(auths.items[i]->refreshToken);
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

    for (size_t i = 0; i < auths.count; i++) {
        char id_buf[32];
        snprintf(id_buf, sizeof(id_buf), "%lld", (long long)auths.items[i]->id);
        print_col(id_buf, w_id);
        printf("  ");

        print_col(auths.items[i]->emailAddress ? auths.items[i]->emailAddress
                                               : "(none)",
                  w_name);
        printf("  ");

        print_col(auths.items[i]->accessToken ? auths.items[i]->accessToken
                                              : "(none)",
                  w_token);
        printf("  ");
        print_col(auths.items[i]->refreshToken ? auths.items[i]->refreshToken
                                               : "(none)",
                  w_refresh);
        printf("  ");

        char exp_buf[32];
        ms_to_timestamp(auths.items[i]->expiresAt, exp_buf, sizeof(exp_buf));
        print_col(exp_buf, w_exp);
        printf("\n");
    }

    printf("\n%zu credential(s)\n", auths.count);
    return 0;
}

int run_add(ClaudeCredentials *current_cred) {
    AUTO_FREE char *email =
        fetch_account_email(current_cred->claudeAiOauth.accessToken);
    if (!email) {
        LOG_ERR("could not fetch account email");
        return -1;
    }

    int needed = snprintf(NULL, 0,
                          "Do you want to add the current claude code account "
                          "with email \"%s\" to your credentials database?",
                          email);
    AUTO_FREE char *add_prompt = malloc(needed + 1);
    if (!add_prompt) {
        LOG_ERR("failed to allocate prompt string");
        return -1;
    }
    snprintf(add_prompt, needed + 1,
             "Do you want to add the current claude code account with email "
             "\"%s\" to your credentials database?",
             email);

    bool should_add = prompt_yes_no(add_prompt);
    if (should_add) {
        AUTO_FREE InternalAuth *existing_auth = get_auth_by_email(email);

        if (existing_auth) {
            free_internal_auth(existing_auth);
            bool should_overwrite =
                prompt_yes_no("Account with this email already exists. do you "
                              "want to overwrite it?");

            if (!should_overwrite) {
                LOG_INFO("nothing done");
                return 0;
            }

            if (update_auth_by_email(current_cred->claudeAiOauth,
                                     current_cred->account, email) == 0) {
                LOG_ERR("failed to update existing credentials");
                return -1;
            }

            LOG_INFO("updated credentials for %s", email);
            return 0;
        }

        uint64_t id =
            insert_auth(current_cred->claudeAiOauth, current_cred->account);
        if (id == 0) {
            LOG_ERR("failed to add new claude credentials");
            return -1;
        }
    }

    return 0;
}

int run_delete(ClaudeCredentials *current_cred) {
    (void)current_cred;

    AUTO_AUTH_LIST AuthList auths = {0};
    auths.items = get_all_claude_oauth_configs(&auths.count);
    if (!auths.items) {
        LOG_ERR("failed to load credentials");
        return 1;
    }

    printf("Delete one of the following credentials:\n\n");

    for (size_t i = 0; i < auths.count; i++) {
        printf("%lld - %s\n", (long long)auths.items[i]->id,
               auths.items[i]->emailAddress ? auths.items[i]->emailAddress
                                            : "(none)");
    }

    printf("\n");

    AUTO_FREE char *id = prompt("ID to delete: ");
    if (!id) {
        LOG_ERR("The ID you provided is not valid.");
        return 1;
    }

    errno = 0;
    char *end;
    unsigned long long val = strtoull(id, &end, 10);

    if (errno == ERANGE) {
        LOG_ERR("The ID you provided is out of range.");
        return 1;
    }
    if (end == id) {
        LOG_ERR("The ID you provided has to be numerical.");
        return 1;
    }
    if (*end != '\0') {
        LOG_ERR("The ID you provided has trailing garbage.");
        return 1;
    }

    if (delete_auth((uint64_t)val) == 0) {
        LOG_ERR("Failed to delete database entry.");
        return 1;
    }

    LOG_INFO("Deleted credential with ID %llu.", (unsigned long long)val);
    return 0;
}

int run_show(ClaudeCredentials *current_cred) {
    printf("Subscription: %s\n",
           current_cred->claudeAiOauth.subscriptionType
               ? current_cred->claudeAiOauth.subscriptionType
               : "(none)");
    printf("Rate limit: %s\n", current_cred->claudeAiOauth.rateLimitTier
                                   ? current_cred->claudeAiOauth.rateLimitTier
                                   : "(none)");

    AUTO_FREE char *email =
        fetch_account_email(current_cred->claudeAiOauth.accessToken);
    if (email) {
        printf("Logged in as: %s\n", email);
    } else {
        LOG_ERR("Failed to fetch account info.");
    }

    return 0;
}

int run_swap(ClaudeCredentials *current_cred) {
    AUTO_FREE char *credentials_path =
        append_to_home(".claude/.credentials.json");
    if (credentials_path == NULL) {
        LOG_ERR("failed to load credentials");
        return 1;
    }

    AUTO_FREE char *claude_path = append_to_home(".claude.json");
    if (claude_path == NULL) {
        LOG_ERR("failed to load credentials");
        return 1;
    }

    AUTO_AUTH_LIST AuthList auths = {0};
    auths.items = get_all_claude_oauth_configs(&auths.count);
    if (!auths.items) {
        LOG_ERR("failed to load credentials");
        return 1;
    }

    printf("Swap your current config with one of the following:\n\n");

    for (size_t i = 0; i < auths.count; i++) {
        printf("%lld - %s\n", (long long)auths.items[i]->id,
               auths.items[i]->emailAddress ? auths.items[i]->emailAddress
                                            : "(none)");
    }

    printf("\n");

    AUTO_FREE char *id = prompt("ID to swap with: ");
    if (!id) {
        LOG_ERR("The ID you provided is not valid.");
        return 1;
    }

    errno = 0;
    char *end;
    unsigned long long val = strtoull(id, &end, 10);

    if (errno == ERANGE) {
        LOG_ERR("The ID you provided is out of range.");
        return 1;
    }
    if (end == id) {
        LOG_ERR("The ID you provided has to be numerical.");
        return 1;
    }
    if (*end != '\0') {
        LOG_ERR("The ID you provided has trailing garbage.");
        return 1;
    }

    AUTO_INTERNAL_AUTH InternalAuth *internal_auth =
        get_auth_by_id((uint64_t)val);
    if (!internal_auth) {
        LOG_ERR("Failed to find the selected credentials.");
        return 1;
    }

    if (current_cred->account.emailAddress) {
        uint32_t updated = update_auth_by_email(
            current_cred->claudeAiOauth, current_cred->account,
            current_cred->account.emailAddress);
        if (updated) {
            LOG_INFO("Updated stored credentials for %s before swapping away",
                     current_cred->account.emailAddress);
        }
    }

    ClaudeCredentials new_cred = {
        .claudeAiOauth =
            {
                .accessToken = dup_str(internal_auth->accessToken),
                .refreshToken = dup_str(internal_auth->refreshToken),
                .expiresAt = internal_auth->expiresAt,
                .refreshTokenExpiresAt = internal_auth->refreshTokenExpiresAt,
                .subscriptionType = dup_str(internal_auth->subscriptionType),
                .rateLimitTier = dup_str(internal_auth->rateLimitTier),
            },
        .account =
            {
                .accountUuid = dup_str(internal_auth->accountUuid),
                .emailAddress = dup_str(internal_auth->emailAddress),
                .organizationUuid = dup_str(internal_auth->organizationUuid),
                .hasExtraUsageEnabled = internal_auth->hasExtraUsageEnabled,
                .billingType = dup_str(internal_auth->billingType),
                .accountCreatedAt = dup_str(internal_auth->accountCreatedAt),
                .subscriptionCreatedAt =
                    dup_str(internal_auth->subscriptionCreatedAt),
                .ccOnboardingFlags = dup_str(internal_auth->ccOnboardingFlags),
                .claudeCodeTrialEndsAt =
                    dup_str(internal_auth->claudeCodeTrialEndsAt),
                .claudeCodeTrialDurationDays =
                    dup_str(internal_auth->claudeCodeTrialDurationDays),
                .seatTier = dup_str(internal_auth->seatTier),
                .displayName = dup_str(internal_auth->displayName),
                .profileFetchedAt = internal_auth->profileFetchedAt,
                .organizationRole = dup_str(internal_auth->organizationRole),
                .workspaceRole = dup_str(internal_auth->workspaceRole),
                .organizationName = dup_str(internal_auth->organizationName),
                .organizationType = dup_str(internal_auth->organizationType),
                .organizationRateLimitTier =
                    dup_str(internal_auth->organizationRateLimitTier),
                .userRateLimitTier = dup_str(internal_auth->userRateLimitTier),
            },
        .mcpOAuth = current_cred->mcpOAuth};

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

    int refresh_result = refresh_oauth_token(&new_cred.claudeAiOauth);
    if (refresh_result < 0) {
        LOG_WARN("Could not refresh tokens for the target account");
        LOG_WARN("If Claude Code reports 'session expired', re-authenticate "
                 "with 'claude' and re-add this account.");
    } else if (refresh_result == 1) {
        LOG_INFO("Successfully refreshed tokens for the target account.");
        if (internal_auth->emailAddress) {
            uint32_t db_updated =
                update_auth_by_email(new_cred.claudeAiOauth,
                                     new_cred.account,
                                     internal_auth->emailAddress);
            if (!db_updated) {
                LOG_WARN("Refreshed tokens were written to the credential "
                         "files but could not be persisted to the database.");
                LOG_WARN("The next swap to this account may need to refresh "
                         "again.");
            }
        }
    }

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

    if (rc != 0) {
        LOG_ERR("Failed to write credentials to file.");
        return 1;
    }
    if (rc2 != 0) {
        LOG_ERR("Failed to write account info to file.");
        return 1;
    }

    LOG_INFO("Swapped config successfully.");

    return 0;
}

int run_completions(const char *shell) {
    if (strcmp(shell, "bash") == 0) {
        printf("_van() {\n"
               "   local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
               "   if [[ $COMP_CWORD -eq 1 ]]; then\n"
               "       COMPREPLY=( $(compgen -W \"list add delete show swap "
               "completions\" -- \"$cur\") )\n"
               "   fi\n"
               "complete -F _van van\n");
        return 0;
    }

    if (strcmp(shell, "zsh") == 0) {
        printf("#compdef van\n"
               "_van() {\n"
               "   local -a commands\n"
               "   commands=(list add delete show swap completions)\n"
               "   if [[ $CURRENT -eq 2 ]]; then\n"
               "       _describe 'command' commands\n"
               "   fi\n"
               "}\n"
               "_van \"$@\"\n");
        return 0;
    }

    if (strcmp(shell, "fish") == 0) {
        printf("complete -c van -f\n"
               "complete -c van -n '__fish_use_subcommand' -a list -d "
               "'List all stored credentials'\n"
               "complete -c van -n '__fish_use_subcommand' -a add -d "
               "'Add current credentials'\n"
               "complete -c van -n '__fish_use_subcommand' -a delete -d "
               "'Delete credentials'\n"
               "complete -c van -n '__fish_use_subcommand' -a show -d "
               "'Show current credentials'\n"
               "complete -c van -n '__fish_use_subcommand' -a swap -d "
               "'Swap config'\n"
               "complete -c van -n '__fish_use_subcommand' -a completions -d "
               "'Generate shell completions'\n");
        return 0;
    }

    LOG_ERR("Unknown shell: %s (supported: bash, zsh, fish)", shell);
    return 1;
}
