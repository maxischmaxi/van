#include "claude.h"
#include "cmd.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "completions") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s completions <bash|zsh|fish>\n", argv[0]);
            return 1;
        }
        return run_completions(argv[2]);
    }

    ClaudeCredentials *current_cred = parse_claude_credentials();
    if (current_cred == NULL) {
        printf("Failed to parse credentials\n");
        return 1;
    }

    const char *list = "    list        List all stored credentials\n";
    const char *add =
        "    add         Add the current credentials to the database\n";
    const char *swap =
        "    swap        Swap your current config with a different one\n";
    const char *completions =
        "    completions Generate shell completion scripts\n";

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "%s", list);
        fprintf(stderr, "%s", add);
        fprintf(stderr, "%s", swap);
        fprintf(stderr, "%s", completions);
        fprintf(stderr, "Your command: %s", *argv);
        free_claude_credentials(current_cred);
        return 1;
    }

    const char *command = argv[1];

    int rc;
    if (strcmp(command, "list") == 0)
        rc = run_list();
    else if (strcmp(command, "add") == 0)
        rc = run_add(current_cred);
    else if (strcmp(command, "delete") == 0)
        rc = run_delete();
    else if (strcmp(command, "show") == 0)
        rc = run_show(current_cred);
    else if (strcmp(command, "swap") == 0)
        return run_swap(current_cred);
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        free_claude_credentials(current_cred);
        return 1;
    }

    free_claude_credentials(current_cred);
    return rc;
}
