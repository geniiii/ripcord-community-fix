#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <funchook.h>

typedef int8_t    i8;
typedef int16_t   i16;
typedef int32_t   i32;
typedef int64_t   i64;
typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef float     f32;
typedef double    f64;
typedef uintptr_t uptr;

#define global                static

#define MacroConcatImpl(x, y) x##y
#define MacroConcat(x, y)     MacroConcatImpl(x, y)
#define Pad(size)             u8 MacroConcat(_pad, __COUNTER__)[size]
#define Unreferenced(x)       (void) x
#define ArrayCount(a)         (sizeof(a) / sizeof((a)[0]))

#define RIPCORD_IMAGE_BASE 0x400000
#define SUPPORTED_VERSION  "0.4.29"

#include "string8.c"
#include "util.c"
#include "ripcord/types.h"
#include "ripcord/functions.h"
#include "hook.c"
#include "main.c"
