#include "claude.h"
#include "cmd.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    int (*fn)(ClaudeCredentials *);
} Command;

static const Command commands[] = {
    {"list", run_list}, {"add", run_add},   {"delete", run_delete},
    {"show", run_show}, {"swap", run_swap},
};

_Static_assert(sizeof(commands) / sizeof(commands[0]) == 5,
               "Command table size mismatch");

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "completions") == 0) {
        if (argc < 3) {
            LOG_ERR("Usage: %s completions <bash|zsh|fish>", argv[0]);
            return 1;
        }
        return run_completions(argv[2]);
    }

    const char *list = "    list        List all stored credentials";
    const char *add =
        "    add         Add the current credentials to the database";
    const char *swap =
        "    swap        Swap your current config with a different one";
    const char *completions =
        "    completions Generate shell completion scripts";

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>", argv[0]);
        fprintf(stderr, "Commands:");
        fprintf(stderr, "%s", list);
        fprintf(stderr, "%s", add);
        fprintf(stderr, "%s", swap);
        fprintf(stderr, "%s", completions);
        fprintf(stderr, "Your command: %s", *argv);
        return 1;
    }

    ClaudeCredentials *current_cred = parse_claude_credentials();
    if (current_cred == NULL) {
        LOG_ERR("Failed to parse credentials");
        return 1;
    }

    int rc = 1;
    const char *command = argv[1];
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if (strcmp(command, commands[i].name) == 0) {
            rc = commands[i].fn(current_cred);
        }
    }

    free_claude_credentials(current_cred);
    return rc;
}
