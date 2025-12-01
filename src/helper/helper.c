/* Vigil Privileged Helper: Minimal root process that applies nftables rulesets
 * 
 * Security model:
 * - Runs as root with CAP_NET_ADMIN to modify netfilter rules
 * - Accepts connections only from local unprivileged agent via Unix socket
 * - Validates ruleset size before processing
 * - Executes nft(8) in child process with stdin fed from pipe
 * - Should drop capabilities and apply seccomp filters after setup (future hardening)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/vigil.sock"
#define DEFAULT_SOCKET_PATH "/tmp/vigil.sock"
#define MAX_RULESET_SIZE (256 * 1024)

void log_msg(const char *msg) {
    fprintf(stderr, "[helper] %s\n", msg);
}

void log_err(const char *msg) {
    fprintf(stderr, "[helper] ERROR: %s: %s\n", msg, strerror(errno));
}

int apply_ruleset(const char *ruleset, size_t ruleset_len) {
    if (access("/usr/sbin/nft", X_OK) != 0 && access("/sbin/nft", X_OK) != 0) {
        log_err("nft command not found or not executable");
        return -1;
    }

    if (ruleset_len == 0 || ruleset_len > MAX_RULESET_SIZE) {
        fprintf(stderr, "[helper] ERROR: Invalid ruleset size: %zu\n", ruleset_len);
        return -1;
    }

    log_msg("Applying new ruleset...");
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        log_err("pipe failed");
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        log_err("fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[1]);
        if (dup2(pipefd[0], STDIN_FILENO) == -1) {
            log_err("dup2 failed");
            exit(EXIT_FAILURE);
        }
        close(pipefd[0]);

        log_msg("Executing 'nft -f -'");
        execlp("nft", "nft", "-f", "-", NULL);
        
        log_err("execlp for nft failed");
        exit(EXIT_FAILURE);
    } else {
        close(pipefd[0]);

        size_t total_written = 0;
        while (total_written < ruleset_len) {
            ssize_t written = write(pipefd[1], ruleset + total_written, ruleset_len - total_written);
            if (written <= 0) {
                log_err("write to pipe failed");
                close(pipefd[1]);
                waitpid(pid, NULL, 0);
                return -1;
            }
            total_written += written;
        }

        close(pipefd[1]);

        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            log_msg("nft command succeeded.");
            return 0;
        } else {
            fprintf(stderr, "[helper] ERROR: nft command failed with status %d\n", WEXITSTATUS(status));
            return -1;
        }
    }
}

static const char *resolve_socket_path(char *buffer, size_t buf_size) {
    const char *env_path = getenv("VIGIL_SOCKET_PATH");
    const char *chosen = (env_path && env_path[0] != '\0') ? env_path : DEFAULT_SOCKET_PATH;

    if (strlen(chosen) >= buf_size) {
        log_msg("VIGIL_SOCKET_PATH is too long for unix socket; falling back to default.");
        chosen = DEFAULT_SOCKET_PATH;
    }

    strncpy(buffer, chosen, buf_size - 1);
    buffer[buf_size - 1] = '\0';
    return buffer;
}

int main() {
    log_msg("Starting privileged helper.");

    if (geteuid() != 0) {
        fprintf(stderr, "[helper] ERROR: This helper must be run as root.\n");
        return EXIT_FAILURE;
    }

    int server_fd, client_fd;
    struct sockaddr_un server_addr;

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        log_err("socket creation failed");
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    const char *socket_path = resolve_socket_path(server_addr.sun_path, sizeof(server_addr.sun_path));

    unlink(socket_path);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) == -1) {
        log_err("bind failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 5) == -1) {
        log_err("listen failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "[helper] Listening on %s\n", socket_path);

    while (1) {
        if ((client_fd = accept(server_fd, NULL, NULL)) == -1) {
            log_err("accept failed");
            continue;
        }

        log_msg("Accepted connection from agent.");

        char *ruleset = malloc(MAX_RULESET_SIZE);
        if (!ruleset) {
            log_err("malloc failed");
            write(client_fd, "FAIL", 4);
            close(client_fd);
            continue;
        }

        size_t total_read = 0;
        ssize_t bytes_read;
        while (total_read < MAX_RULESET_SIZE) {
            bytes_read = read(client_fd, ruleset + total_read, MAX_RULESET_SIZE - total_read);
            if (bytes_read < 0) {
                log_err("read failed");
                break;
            }
            if (bytes_read == 0) break;
            total_read += bytes_read;
        }

        if (total_read > 0 && total_read < MAX_RULESET_SIZE) {
            ruleset[total_read] = '\0';
            if (apply_ruleset(ruleset, total_read) == 0) {
                write(client_fd, "OK", 2);
            } else {
                write(client_fd, "FAIL", 4);
            }
        } else if (total_read >= MAX_RULESET_SIZE) {
            log_msg("Ruleset too large, rejecting.");
            write(client_fd, "FAIL", 4);
        } else {
            log_err("No data received from client");
            write(client_fd, "FAIL", 4);
        }

        free(ruleset);
        close(client_fd);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}