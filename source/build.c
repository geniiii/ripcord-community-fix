#define COBJMACROS
#define VC_EXTRALEAN
#define NOATOM
#define NOHELP
#define NOPROFILER
#define NOGDICAPMASKS
#define NOSERVICE
#define NOMETAFILE
#define NOMINMAX
#define NOKANJI
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
#include <winhttp.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <setupapi.h>
#include <dwmapi.h>
#include <wchar.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <mfapi.h>
#include <mftransform.h>
#include <mfidl.h>
#include <mferror.h>
#include <strmif.h>
#include <codecapi.h>
#include <wmcodecdsp.h>
#include <oleauto.h>
#include <timeapi.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audioclientactivationparams.h>
#include "ext/minhook/src/hde/hde64.c"
#include "ext/minhook/src/buffer.c"
#include "ext/minhook/src/hook.c"
#include "ext/minhook/src/trampoline.c"
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

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
#define ReadU16BE(a)          ((u16) (((a)[0] << 8) | (a)[1]))
#define ReadU32BE(a)          (((u32) (a)[0] << 24) | ((u32) (a)[1] << 16) | ((u32) (a)[2] << 8) | (u32) (a)[3])

#define SUPPORTED_VERSION     "0.4.29"

#define VERSION               "1.12.1"

#define JSMN_STATIC
#include "ext/jsmn.h"
#include "string8.c"
#include "log.c"
#include "json.c"
#include "update.c"
#include "discord/protocol.h"
#include "qt/types.h"
#include "qt/functions.h"
#include "ripcord/types.h"
#include "ripcord/functions.h"
#include "qt/json.c"
#include "ripcord/db.c"
#include "ripcord/erf.c"
#include "ripcord/evlog.c"
#include "op.c"
#include "sodium.h"
#include "dave/dave.h"
#include "dave/state.c"
#include "dave/send.c"
#include "dave/crypto.c"
#include "dave/session.c"
#include "dave/mls.c"
#include "screenshare/types.h"
#include "screenshare/sources.c"
#include "screenshare/h264.c"
#include "screenshare/engine.h"
#include "screenshare/encoder.c"
#include "screenshare/capture.c"
#include "screenshare/stream.h"
#include "screenshare/stream_rtp.c"
#include "screenshare/stream.c"
#include "screenshare/audio.c"
#include "screenshare/golive.c"
#include "screenshare/picker.c"
#include "hooks/voice_line.c"
#include "hooks/network.c"
#include "hooks/users.c"
#include "hooks/guilds.c"
#include "hooks/erf.c"
#include "hooks/sidebar.c"
#include "hooks/http.c"
#include "hooks/gateway.c"
#include "hooks/voice_gateway.c"
#include "hooks/voice_send.c"
#include "hooks/voice_receive.c"
#include "hooks/ded.c"
#include "hooks/restrict.c"
#include "hook.c"
#include "main.c"
