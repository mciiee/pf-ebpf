#ifndef LOG_H
#define LOG_H

#ifndef ERROR_PREFIX
#define ERROR_PREFIX "[ERROR] "
#endif

#ifndef LOG_PREFIX
#define LOG_PREFIX "[LOG] "
#endif

#ifndef LOG_PRINT
#define LOG_PRINT(template, ...) printf(LOG_PREFIX template __VA_OPT__(,) __VA_ARGS__)
#endif

#ifndef LOG_ERROR
#define LOG_ERROR(template, ...) fprintf(stderr, ERROR_PREFIX template __VA_OPT__(,) __VA_ARGS__)
#endif

#endif
