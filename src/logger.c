#include "../include/logger.h"
#include <stdarg.h>

void pretty_print(log_level_t level, const char* format, ...) {
    if (!format) {
        fprintf(stderr, "[!] Invalid format string\n");
        return;
    }
    
    const char* prefix;
    FILE* output_stream;
    
    switch (level) {
        case LOG_ERROR:
            prefix = "[!]";
            output_stream = stderr;
            break;
        case LOG_SUCCESS:
            prefix = "[+]";
            output_stream = stdout;
            break;
        case LOG_INFO:
            prefix = "[i]";
            output_stream = stdout;
            break;
        case LOG_WARNING:
            prefix = "[w]";
            output_stream = stderr;
            break;
        default:
            prefix = "[?]";
            output_stream = stderr;
            break;
    }
    
    va_list args;
    va_start(args, format);
    
    fprintf(output_stream, "%s ", prefix);
    vfprintf(output_stream, format, args);
    fprintf(output_stream, "\n");
    
    va_end(args);
    fflush(output_stream);
}

void print_binary_data(const BYTE* data, DWORD size) {
    if (!data) {
        pretty_print(LOG_ERROR, "Invalid data pointer");
        return;
    }
    
    printf("[i] Binary data (%lu bytes): ", size);
    for (DWORD i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
}
