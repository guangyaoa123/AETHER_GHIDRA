#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int socket_fd;
    uint32_t state;
    uint64_t bytes_processed;
    char peer_name[32];
} Connection;

__attribute__((noinline)) static void connection_init(Connection *connection, int fd, const char *peer) {
    memset(connection, 0, sizeof(*connection));
    connection->socket_fd = fd;
    connection->state = 1;
    strncpy(connection->peer_name, peer, sizeof(connection->peer_name) - 1);
}

__attribute__((noinline)) static int connection_consume(Connection *connection, const unsigned char *data, size_t length) {
    if (connection->state != 1 || data == NULL) {
        return -1;
    }
    for (size_t index = 0; index < length; ++index) {
        connection->bytes_processed += data[index];
    }
    return (int)connection->bytes_processed;
}

__attribute__((noinline)) static void connection_close(Connection *connection) {
    connection->state = 3;
    connection->socket_fd = -1;
}

int main(int argc, char **argv) {
    Connection connection;
    const char *peer = argc > 1 ? argv[1] : "local";
    connection_init(&connection, 7, peer);
    int result = connection_consume(&connection, (const unsigned char *)peer, strlen(peer));
    connection_close(&connection);
    printf("%s:%d\n", connection.peer_name, result);
    return result < 0;
}
