#include "cJSON.h"
#include "claude.h"
#include "cmd.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *path = append_to_home(".claude/.credentials.json");
    if (path == NULL) {
        fprintf(stderr, "Could not find claude credentials.\n");
        fprintf(stderr,
                "Please install claude code and sign in to use this tool.");
        return 1;
    }

    cJSON *root = parse_credentials_file(path);
    if (root == NULL) {
        fprintf(stderr, "Failed to parse %s", path);
        free(path);
        return 1;
    }

    ClaudeCredentials *current_cred = parse_claude_credentials(root);
    if (current_cred == NULL) {
        printf("Failed to parse credentials\n");
        cJSON_Delete(root);
        free(path);
        return 1;
    }
    cJSON_Delete(root);

    const char *list = "    list        List all stored credentials\n";
    const char *add =
        "    add         Add the current credentials to the database\n";
    const char *rename = "    rename      Rename a existing database entry\n";
    const char *swap =
        "    swap        Swap your current config with a different one\n";

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "%s", list);
        fprintf(stderr, "%s", add);
        fprintf(stderr, "%s", rename);
        fprintf(stderr, "%s", swap);
        fprintf(stderr, "Your command: %s", *argv);
        free(path);
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "list") == 0)
        return run_list(current_cred);
    if (strcmp(command, "add") == 0)
        return run_add(current_cred);
    if (strcmp(command, "delete") == 0)
        return run_delete(current_cred);
    if (strcmp(command, "show") == 0)
        return run_show(current_cred);
    if (strcmp(command, "rename") == 0)
        return run_rename(current_cred);
    if (strcmp(command, "swap") == 0)
        return run_swap(current_cred, path);

    fprintf(stderr, "Unknown command: %s\n", command);
    free(path);
    return 1;
}
