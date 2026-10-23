#define main vigil_helper_main
#include "../src/helper/helper.c"
#undef main
#include <assert.h>

static const char *expected_script;
static size_t expected_size;
static int apply_calls;
static int apply_result;

static int fake_apply(const char *script, size_t length) {
    ++apply_calls;
    assert(length == expected_size);
    assert(memcmp(script, expected_script, length) == 0);
    return apply_result;
}

static void exercise(uint32_t declared, const char *body, size_t actual,
                     size_t header_bytes, int success, int expected_calls) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    expected_script = body;
    expected_size = actual;
    apply_calls = 0;
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(sockets[0]);
        uint32_t header = htonl(declared);
        const char *bytes = (const char *)&header;
        for (size_t i = 0; i < header_bytes; ++i) {
            assert(write_all(sockets[1], bytes + i, 1) == 0);
        }
        size_t sent = 0;
        while (sent < actual) {
            size_t count = actual - sent;
            if (count > 113) count = 113;
            assert(write_all(sockets[1], body + sent, count) == 0);
            sent += count;
        }
        /* Keep writes open to detect EOF-based deadlocks. */
        if (header_bytes < 4 || actual < declared) {
            assert(shutdown(sockets[1], SHUT_WR) == 0);
        }
        char reply[4];
        size_t reply_size = success ? 2 : 4;
        assert(read_exact(sockets[1], reply, reply_size) == 0);
        assert(memcmp(reply, success ? "OK" : "FAIL", reply_size) == 0);
        close(sockets[1]);
        _exit(0);
    }
    close(sockets[1]);
    int result = handle_client(sockets[0], getuid(), fake_apply);
    assert((result == 0) == success);
    assert(apply_calls == expected_calls);
    close(sockets[0]);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    alarm(15);
    uid_t uid;
    assert(parse_agent_uid("1000", &uid) == 0 && uid == 1000);
    assert(parse_agent_uid("0", &uid) == 0 && uid == 0);
    const char *invalid[] = { "", "-1", "+1", " 1", "1x", "4294967295", "99999999999999999999999999" };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        assert(parse_agent_uid(invalid[i], &uid) == -1);
    }
    assert(authorized_uid(0, 1000));
    assert(authorized_uid(1000, 1000));
    assert(!authorized_uid(1001, 1000));
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(peer_uid(sockets[0], &uid) == 0 && uid == getuid());
    close(sockets[0]);
    close(sockets[1]);

    const char *script = "table inet vigilfw {}\n";
    size_t length = strlen(script);
    exercise((uint32_t)length, script, length, 4, 1, 1);
    exercise(0, "", 0, 4, 0, 0);
    exercise(MAX_RULESET_SIZE + 1, "", 0, 4, 0, 0);
    exercise((uint32_t)length, "", 0, 2, 0, 0);
    exercise((uint32_t)length, script, length - 1, 4, 0, 0);
    const char nul[] = {'a', '\0', 'b'};
    exercise(sizeof(nul), nul, sizeof(nul), 4, 0, 0);
    apply_result = -1;
    exercise((uint32_t)length, script, length, 4, 0, 1);
    apply_result = 0;
    char *maximum = malloc(MAX_RULESET_SIZE);
    assert(maximum);
    memset(maximum, 'x', MAX_RULESET_SIZE);
    exercise(MAX_RULESET_SIZE, maximum, MAX_RULESET_SIZE, 4, 1, 1);
    free(maximum);
    puts("Helper tests passed (UID authorization, peer credentials, framing, limits, truncation and apply failures)");
    return 0;
}
