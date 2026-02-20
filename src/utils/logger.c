#include "../../include/utils/logger.h"

//////////////////////////////////////////////////////////////
// Output Functions //////////////////////////////////////////
//////////////////////////////////////////////////////////////

/**
 * Function to display the tool banner
 */
void print_banner(void) {
    printf("\n");
    printf("  ____            _     _             _\n");
    printf(" |  _ \\ ___  __ _(_)___| |_ _ __ __ _| |_ ___  _ __\n");
    printf(" | |_) / _ \\/ _` | / __| __| '__/ _` | __/ _ \\| '__|\n");
    printf(" |  _ <  __/ (_| | \\__ \\ |_| | | (_| | || (_) | |\n");
    printf(" |_| \\_\\___|\\__, |_|___/\\__|_|  \\__,_|\\__\\___/|_|\n");
    printf("            |___/\n");
    printf("\n");
    printf("  +---------------------------------------------------------+\n");
    printf("  |                                                         |\n");
    printf("  |  Description : %-40s |\n", TOOL_DESC);
    printf("  |  Version     : %-40s |\n", TOOL_VERSION);
    printf("  |  Author      : %-40s |\n", TOOL_AUTHOR);
    printf("  |  Target      : %-40s |\n", "Windows x64 (requires elevation)");
    printf("  |                                                         |\n");
    printf("  +---------------------------------------------------------+\n");
    printf("\n");
}

/**
 * Function to display outputs with different status
 * @param level: Logging level
 * @param format: Content to display with extensive parameters
 */
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

/**
 * Function to display correctly binary data from registry keys
 * @param data: Data content to display
 * @param size: Size of the binary word to display
 */
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
