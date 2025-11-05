#define VC_EXTRALEAN
#define NOATOM
#define NOHELP
#define NOPROFILER
#define NOGDICAPMASKS
#define NOATOM
#define NOSERVICE
#define NOMETAFILE
#define NOMINMAX
#define NOKANJI
#define NODRAWTEXT
#define NOCOLOR
#define NOSYSMETRICS
#define NOMENUS
#define NOKEYSTATES
#define NOWH
#define NOCOMM
#define NOMCX
#define NOIME
#define NODEFERWINDOWPOS
#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Ntsecapi.h>
#include "ext/minhook/MinHook.c"
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

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

#define MacroConcatImpl(x, y) x##y
#define MacroConcat(x, y) MacroConcatImpl(x, y)
#define Pad(size) u8 MacroConcat(_pad, __COUNTER__)[size]
#define Unreferenced(x) (void) x

#define HIJACKED_DLL      "winmm.dll"
#define SUPPORTED_VERSION "0.4.29"

#include "util.c"
#include "string8.c"
#include "qt/types.h"
#include "qt/functions.h"
#include "ripcord/types.h"
#include "ripcord/functions.h"
#include "sodium.h"
#include "hook.c"
#include "main.c"
