#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>

#define DEFAULT_SOCKET_PATH "/tmp/vigil.sock"
#define BUF_SIZE 8192

void log_msg(const char *msg) {
    fprintf(stderr, "[helper] %s\n", msg);
}

void log_err(const char *msg) {
    fprintf(stderr, "[helper] ERROR: %s: %s\n", msg, strerror(errno));
}

int apply_ruleset(const char *ruleset) {
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
        // child
        close(pipefd[1]);
        // redirect stdin to read end of pipe
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);

        // TODO: add capability dropping and seccomp filters 
        log_msg("Executing 'nft -f -'");
        execlp("nft", "nft", "-f", "-", NULL);
        
        log_err("execlp for nft failed");
        exit(EXIT_FAILURE);
    } else {
        // parent
        close(pipefd[0]);

        // write ruleset to the pipe
        ssize_t total_written = 0;
        while (total_written < strlen(ruleset)) {
            ssize_t written = write(pipefd[1], ruleset + total_written, strlen(ruleset) - total_written);
            if (written < 0) {
                log_err("write to pipe failed");
                break;
            }
            total_written += written;
        }

        if (access("/usr/sbin/nft", X_OK) != 0) {
            log_err("nft command not found or not executable");
            return -1;
        }

        // close pipe to send EOF to child
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

    // check if running as root
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

    // remove old socket if exists
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
        
        char buffer[BUF_SIZE] = {0};
        ssize_t bytes_read = read(client_fd, buffer, BUF_SIZE - 1);

        if (bytes_read > 0) {
            buffer[bytes_read] = '\0'; // Null-terminate
            if (apply_ruleset(buffer) == 0) {
                write(client_fd, "OK", 2);
            } else {
                write(client_fd, "FAIL", 4);
            }
        } else {
            log_err("read from client failed");
        }

        close(client_fd);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}