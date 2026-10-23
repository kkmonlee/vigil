#include <sqlite3.h>

/* Keep SQLITE_TRANSIENT's unaligned sentinel cast in C. */
int vigil_sqlite_bind_text(sqlite3_stmt *stmt, int index, const char *text, int length) {
    return sqlite3_bind_text(stmt, index, text, length, SQLITE_TRANSIENT);
}
