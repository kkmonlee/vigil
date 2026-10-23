#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_SOCKET_PATH "/run/vigil/helper.sock"
#define MAX_RULESET_SIZE (256 * 1024)
#define CLIENT_TIMEOUT_SECONDS 5

typedef int (*ruleset_applier)(const char *, size_t);
static volatile sig_atomic_t stopping;

static void stop_helper(int sig) {
    (void)sig;
    stopping = 1;
}

static void log_err(const char *msg) {
    fprintf(stderr, "[helper] %s: %s\n", msg, strerror(errno));
}

static int read_exact(int fd, void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = read(fd, (char *)buffer + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (size_t)n;
    }
    return 0;
}

static int write_all(int fd, const void *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = write(fd, (const char *)buffer + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (size_t)n;
    }
    return 0;
}

static int parse_agent_uid(const char *value, uid_t *uid) {
    if (!value || !*value) return -1;
    for (const char *p = value; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
    }
    errno = 0;
    char *end;
    uintmax_t parsed = strtoumax(value, &end, 10);
    if (errno || *end || parsed >= (uintmax_t)(uid_t)-1) return -1;
    *uid = (uid_t)parsed;
    return 0;
}

static int peer_uid(int fd, uid_t *uid) {
#if defined(__linux__)
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) return -1;
    *uid = credentials.uid;
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    gid_t gid;
    return getpeereid(fd, uid, &gid);
#else
    (void)fd;
    (void)uid;
    errno = ENOTSUP;
    return -1;
#endif
}

static int authorized_uid(uid_t uid, uid_t agent_uid) {
    return uid == 0 || uid == agent_uid;
}

static int apply_ruleset(const char *ruleset, size_t ruleset_len) {
    const char *nft = "/usr/sbin/nft";
    if (access(nft, X_OK) != 0) nft = "/sbin/nft";
    if (access(nft, X_OK) != 0) {
        log_err("nft executable not found");
        return -1;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) return -1;
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[1]);
        if (dup2(pipefd[0], STDIN_FILENO) == -1) _exit(127);
        close(pipefd[0]);
        execl(nft, nft, "-f", "-", (char *)NULL);
        _exit(127);
    }

    close(pipefd[0]);
    int written = write_all(pipefd[1], ruleset, ruleset_len);
    close(pipefd[1]);
    int status;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    if (written != 0 || waited != pid) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int handle_client(int fd, uid_t agent_uid, ruleset_applier apply) {
    uid_t uid;
    if (peer_uid(fd, &uid) != 0 || !authorized_uid(uid, agent_uid)) {
        fprintf(stderr, "[helper] Rejected unauthorized peer\n");
        (void)write_all(fd, "FAIL", 4);
        return -1;
    }
    struct timeval timeout = { .tv_sec = CLIENT_TIMEOUT_SECONDS };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        return -1;
    }

    uint32_t wire_length;
    if (read_exact(fd, &wire_length, sizeof(wire_length)) != 0) goto reject;
    size_t length = ntohl(wire_length);
    if (length == 0 || length > MAX_RULESET_SIZE) goto reject;

    char *ruleset = malloc(length);
    if (!ruleset) goto reject;
    int result = -1;
    if (read_exact(fd, ruleset, length) == 0 && !memchr(ruleset, '\0', length)) {
        result = apply(ruleset, length);
    }
    free(ruleset);
    (void)write_all(fd, result == 0 ? "OK" : "FAIL", result == 0 ? 2 : 4);
    return result;

reject:
    (void)write_all(fd, "FAIL", 4);
    return -1;
}

static int prepare_socket_directory(const char *path) {
    char directory[sizeof(((struct sockaddr_un *)0)->sun_path)];
    const char *slash = strrchr(path, '/');
    if (!slash || path[0] != '/' || !slash[1] || slash == path) {
        errno = EINVAL;
        return -1;
    }
    size_t length = (size_t)(slash - path);
    memcpy(directory, path, length);
    directory[length] = '\0';
    if (strcmp(directory, "/run/vigil") == 0 &&
        mkdir(directory, 0755) != 0 && errno != EEXIST) return -1;
    struct stat st;
    if (lstat(directory, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022)) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int main(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "[helper] Must run as root\n");
        return EXIT_FAILURE;
    }
    uid_t agent_uid = 0;
    const char *uid_env = getenv("VIGIL_AGENT_UID");
    if (uid_env && parse_agent_uid(uid_env, &agent_uid) != 0) {
        fprintf(stderr, "[helper] VIGIL_AGENT_UID must be a numeric UID\n");
        return EXIT_FAILURE;
    }
    const char *socket_path = getenv("VIGIL_SOCKET_PATH");
    if (!socket_path) socket_path = DEFAULT_SOCKET_PATH;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(socket_path) >= sizeof(address.sun_path) ||
        prepare_socket_directory(socket_path) != 0) {
        fprintf(stderr, "[helper] Socket requires a root-owned runtime directory without group/other write access\n");
        return EXIT_FAILURE;
    }
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    signal(SIGPIPE, SIG_IGN);
    umask(0077);

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server == -1) return EXIT_FAILURE;
    if (fcntl(server, F_SETFD, FD_CLOEXEC) == -1 ||
        bind(server, (struct sockaddr *)&address, sizeof(address)) == -1) {
        log_err("Failed to bind helper socket (remove a stale socket explicitly)");
        close(server);
        return EXIT_FAILURE;
    }
    if (chown(socket_path, agent_uid, (gid_t)-1) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(server, 5) != 0) {
        log_err("Failed to secure helper socket");
        close(server);
        unlink(socket_path);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "[helper] Listening on %s for UID %ju and root\n",
            socket_path, (uintmax_t)agent_uid);
    struct sigaction action = {0};
    action.sa_handler = stop_helper;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0) {
        close(server);
        unlink(socket_path);
        return EXIT_FAILURE;
    }
    while (!stopping) {
        int client = accept(server, NULL, NULL);
        if (client == -1) {
            if (errno == EINTR) continue;
            log_err("accept failed");
            continue;
        }
        if (fcntl(client, F_SETFD, FD_CLOEXEC) != -1) {
            (void)handle_client(client, agent_uid, apply_ruleset);
        }
        close(client);
    }
    close(server);
    unlink(socket_path);
    return EXIT_SUCCESS;
}
