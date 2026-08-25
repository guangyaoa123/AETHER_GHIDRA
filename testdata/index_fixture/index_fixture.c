/*
 * Small standalone fixture for exercising AETHER whole-program indexing.
 * It intentionally contains recognizable operations without external runtime
 * dependencies beyond libc and pthreads.
 */
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char host[64];
    unsigned port;
    int secure;
} endpoint_t;

typedef struct {
    uint8_t *data;
    size_t length;
    uint8_t key;
} transform_job_t;

__attribute__((noinline)) static uint32_t fnv1a32(const char *text) {
    uint32_t hash = 2166136261u;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; ++cursor) {
        hash ^= *cursor;
        hash *= 16777619u;
    }
    return hash;
}

__attribute__((noinline)) static int parse_endpoint(const char *text, endpoint_t *endpoint) {
    char scheme[8] = {0};
    unsigned port = 0;
    if (sscanf(text, "%7[^:]://%63[^:]:%u", scheme, endpoint->host, &port) != 3) {
        return -1;
    }
    endpoint->port = port;
    endpoint->secure = strcmp(scheme, "https") == 0;
    return endpoint->port > 0 && endpoint->port < 65536 ? 0 : -1;
}

__attribute__((noinline)) static int read_configuration(const char *path, endpoint_t *endpoint) {
    FILE *file = fopen(path, "r");
    if (!file) {
        return -1;
    }
    char line[256];
    int result = -1;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "endpoint=", 9) == 0 && parse_endpoint(line + 9, endpoint) == 0) {
            result = 0;
            break;
        }
    }
    fclose(file);
    return result;
}

__attribute__((noinline)) static void xor_transform(uint8_t *data, size_t length, uint8_t key) {
    for (size_t index = 0; index < length; ++index) {
        data[index] ^= (uint8_t)(key + (index * 31u));
    }
}

__attribute__((noinline)) static void *transform_worker(void *argument) {
    transform_job_t *job = (transform_job_t *)argument;
    xor_transform(job->data, job->length, job->key);
    return NULL;
}

__attribute__((noinline)) static int threaded_transform(uint8_t *data, size_t length, uint8_t key) {
    transform_job_t job = {data, length, key};
    pthread_t thread;
    if (pthread_create(&thread, NULL, transform_worker, &job) != 0) {
        return -1;
    }
    return pthread_join(thread, NULL);
}

__attribute__((noinline)) static int write_report(const char *path, const endpoint_t *endpoint, uint32_t digest) {
    FILE *file = fopen(path, "w");
    if (!file) {
        return -1;
    }
    int result = fprintf(file, "host=%s\nport=%u\nsecure=%d\ndigest=%08x\n",
        endpoint->host, endpoint->port, endpoint->secure, digest) < 0 ? -1 : 0;
    fclose(file);
    return result;
}

__attribute__((noinline)) static int dispatch_request(const char *command, endpoint_t *endpoint) {
    if (strcmp(command, "connect") == 0) {
        return endpoint->secure ? 443 : 80;
    }
    if (strcmp(command, "status") == 0) {
        return endpoint->port;
    }
    return -1;
}

__attribute__((noinline)) static int run_fixture(const char *config_path, const char *report_path) {
    endpoint_t endpoint = {0};
    if (read_configuration(config_path, &endpoint) != 0) {
        strcpy(endpoint.host, "127.0.0.1");
        endpoint.port = 8080;
        endpoint.secure = 0;
    }

    uint8_t payload[] = "aether-index-fixture";
    uint32_t digest = fnv1a32((const char *)payload);
    if (threaded_transform(payload, sizeof(payload) - 1, 0x5a) != 0) {
        return -1;
    }
    if (write_report(report_path, &endpoint, digest) != 0) {
        return -1;
    }
    return dispatch_request("connect", &endpoint) > 0 ? payload[0] : -1;
}

int main(int argc, char **argv) {
    const char *config_path = argc > 1 ? argv[1] : "index-fixture.conf";
    const char *report_path = argc > 2 ? argv[2] : "index-fixture.report";
    return run_fixture(config_path, report_path) == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}
