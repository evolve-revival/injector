#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Vanilla RSA-1024 PKCS#1 public key (140 bytes) — scan target in game memory */
static const uint8_t VANILLA_KEY[140] = {
    0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xa2,0xd1,0x1f,0x0c,0x51,0xfa,0x6b,0x45,0x1d,
    0x7e,0x05,0xfe,0x3f,0x06,0x72,0x56,0x10,0xa9,0xa7,0x7b,0x67,0x4f,0xb6,0x65,0xf4,
    0xa1,0x2b,0xcf,0x07,0xcd,0x94,0x4f,0x6e,0xbf,0x9d,0xf3,0x0f,0xcc,0x7b,0x63,0xeb,
    0x3d,0xa5,0xe6,0x59,0x52,0x3a,0xa7,0xd8,0x54,0xac,0x38,0x9d,0x59,0x22,0x69,0x3b,
    0xba,0x59,0x9e,0x82,0x95,0x12,0x72,0xd7,0x1f,0x1f,0x55,0x43,0x4b,0x7b,0xbc,0x9c,
    0xdd,0xe6,0x05,0x07,0x71,0x4c,0xe5,0x3d,0x84,0x11,0xf9,0x1a,0xb0,0xc1,0x24,0x90,
    0x5a,0xde,0x7b,0x24,0x9e,0x98,0x86,0x06,0x35,0x1a,0xef,0x2c,0x59,0xf5,0xf4,0xca,
    0x28,0xca,0x3c,0x7a,0xcb,0xe7,0x7a,0xa5,0x56,0x91,0xe0,0x98,0x4e,0x16,0x43,0x36,
    0x24,0xa1,0x5b,0xe3,0x75,0xb0,0x53,0x02,0x03,0x01,0x00,0x01
};

static HMODULE real_dbghelp = NULL;
static char    g_dll_path[MAX_PATH];

/* ------------------------------------------------------------------ */
/* Real dbghelp lazy loader (avoids LoadLibraryA inside DllMain)       */
/* ------------------------------------------------------------------ */

static HMODULE get_real_dbghelp(void)
{
    if (!real_dbghelp) {
        char sys_path[MAX_PATH];
        GetSystemDirectoryA(sys_path, MAX_PATH);
        strncat(sys_path, "\\dbghelp.dll", MAX_PATH - strlen(sys_path) - 1);
        real_dbghelp = LoadLibraryA(sys_path);
    }
    return real_dbghelp;
}

/* ------------------------------------------------------------------ */
/* Logging                                                              */
/* ------------------------------------------------------------------ */

static void log_msg(const char *dll_path, const char *msg)
{
    char log_path[MAX_PATH];
    strncpy(log_path, dll_path, MAX_PATH - 1);
    log_path[MAX_PATH - 1] = '\0';
    char *sep = strrchr(log_path, '\\');
    if (sep) {
        size_t dir_len = (size_t)(sep + 1 - log_path);
        snprintf(sep + 1, MAX_PATH - dir_len, "revival_inject.log");
    }

    FILE *f = fopen(log_path, "a");
    if (!f) return;
    fprintf(f, "[revival-inject] %s\n", msg);
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Memory scan + patch                                                  */
/* ------------------------------------------------------------------ */

#define PAGE_READABLE (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | \
                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

static void scan_and_patch(const char *dll_path, const uint8_t *new_key)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = (uint8_t *)si.lpMinimumApplicationAddress;
    int patches = 0;

    while (addr < (uint8_t *)si.lpMaximumApplicationAddress) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_READABLE) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize >= 140)
        {
            uint8_t *base = (uint8_t *)mbi.BaseAddress;
            SIZE_T  size  = mbi.RegionSize;

            for (SIZE_T i = 0; i + 140 <= size; i++) {
                /* Skip our own .rdata copy to avoid self-corruption */
                if (base + i == VANILLA_KEY) continue;
                if (memcmp(base + i, VANILLA_KEY, 140) == 0) {
                    DWORD old_prot;
                    if (VirtualProtect(base + i, 140, PAGE_READWRITE, &old_prot)) {
                        memcpy(base + i, new_key, 140);
                        VirtualProtect(base + i, 140, old_prot, &old_prot);
                        patches++;
                        char buf[64];
                        snprintf(buf, sizeof(buf), "patched vanilla key at %p", (void *)(base + i));
                        log_msg(dll_path, buf);
                    }
                }
            }
        }

        addr += mbi.RegionSize;
    }

    if (patches == 0)
        log_msg(dll_path, "vanilla key not found in memory (may already be patched or key changed)");
}

/* ------------------------------------------------------------------ */
/* DllMain                                                              */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    if (reason != DLL_PROCESS_ATTACH) return TRUE;

    GetModuleFileNameA(hInst, g_dll_path, MAX_PATH);

    /* Build path to revival.pub (same directory as this DLL) */
    char pub_path[MAX_PATH];
    strncpy(pub_path, g_dll_path, MAX_PATH - 1);
    pub_path[MAX_PATH - 1] = '\0';
    char *sep = strrchr(pub_path, '\\');
    if (!sep) {
        log_msg(g_dll_path, "ERROR: cannot determine DLL directory");
        return TRUE;
    }
    strcpy(sep + 1, "revival.pub");

    FILE *f = fopen(pub_path, "rb");
    if (!f) {
        log_msg(g_dll_path, "revival.pub not found — loading game with vanilla key");
        return TRUE;
    }
    uint8_t pub_key[140];
    size_t n = fread(pub_key, 1, 140, f);
    fclose(f);

    if (n != 140) {
        log_msg(g_dll_path, "ERROR: revival.pub is not 140 bytes — expected PKCS#1 DER RSA-1024 public key");
        return TRUE;
    }

    log_msg(g_dll_path, "revival.pub loaded — scanning memory for vanilla key");
    scan_and_patch(g_dll_path, pub_key);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Export stubs — forward to real dbghelp.dll via lazy load            */
/* ------------------------------------------------------------------ */

#define STUB(ret, name, params, args, fail_ret)                          \
    typedef ret (WINAPI *name##_t) params;                               \
    ret WINAPI name params {                                             \
        static name##_t fn = NULL;                                       \
        if (!fn) {                                                        \
            HMODULE h = get_real_dbghelp();                              \
            if (h) fn = (name##_t)GetProcAddress(h, #name);             \
        }                                                                 \
        if (!fn) return fail_ret;                                        \
        return fn args;                                                  \
    }

STUB(BOOL,   SymInitialize,           (HANDLE hp, PCSTR sp, BOOL inv),                               (hp,sp,inv),          FALSE)
STUB(BOOL,   SymCleanup,              (HANDLE hp),                                                   (hp),                 FALSE)
STUB(DWORD,  SymGetOptions,           (void),                                                        (),                   0)
STUB(DWORD,  SymSetOptions,           (DWORD opts),                                                  (opts),               0)
STUB(BOOL,   SymGetSearchPath,        (HANDLE hp, PSTR buf, DWORD len),                              (hp,buf,len),         FALSE)
STUB(BOOL,   SymSetSearchPath,        (HANDLE hp, PCSTR path),                                       (hp,path),            FALSE)
STUB(BOOL,   SymFromAddr,             (HANDLE hp, DWORD64 addr, PDWORD64 disp, PSYMBOL_INFO si),     (hp,addr,disp,si),    FALSE)
STUB(BOOL,   SymGetLineFromAddr64,    (HANDLE hp, DWORD64 addr, PDWORD disp, PIMAGEHLP_LINE64 ln),   (hp,addr,disp,ln),    FALSE)
STUB(DWORD64,SymGetModuleBase64,      (HANDLE hp, DWORD64 addr),                                     (hp,addr),            0)
STUB(BOOL,   SymGetModuleInfo64,      (HANDLE hp, DWORD64 addr, PIMAGEHLP_MODULE64 mi),              (hp,addr,mi),         FALSE)
STUB(DWORD64,SymLoadModule64,         (HANDLE hp, HANDLE fh, PCSTR img, PCSTR mod, DWORD64 base, DWORD sz), (hp,fh,img,mod,base,sz), 0)
STUB(BOOL,   SymUnloadModule64,       (HANDLE hp, DWORD64 base),                                     (hp,base),            FALSE)
STUB(PVOID,  SymFunctionTableAccess64,(HANDLE hp, DWORD64 addr),                                     (hp,addr),            NULL)
STUB(BOOL,   SymEnumerateModules64,   (HANDLE hp, PSYM_ENUMMODULES_CALLBACK64 cb, PVOID ctx),        (hp,cb,ctx),          FALSE)
STUB(BOOL,   SearchTreeForFile,       (PSTR root, PSTR in, PSTR out),                                (root,in,out),        FALSE)
STUB(BOOL,   StackWalk64,             (DWORD mt, HANDLE hp, HANDLE ht, LPSTACKFRAME64 sf, PVOID ctx, PREAD_PROCESS_MEMORY_ROUTINE64 rm, PFUNCTION_TABLE_ACCESS_ROUTINE64 fta, PGET_MODULE_BASE_ROUTINE64 gmb, PTRANSLATE_ADDRESS_ROUTINE64 ta), (mt,hp,ht,sf,ctx,rm,fta,gmb,ta), FALSE)
STUB(BOOL,   SymGetSymFromAddr64,     (HANDLE hp, DWORD64 addr, PDWORD64 disp, PIMAGEHLP_SYMBOL64 sym), (hp,addr,disp,sym), FALSE)
STUB(DWORD,  UnDecorateSymbolName,    (PCSTR dec, PSTR out, DWORD sz, DWORD flags),                  (dec,out,sz,flags),   0)
STUB(BOOL,   MiniDumpWriteDump,       (HANDLE hp, DWORD pid, HANDLE hf, MINIDUMP_TYPE type, PMINIDUMP_EXCEPTION_INFORMATION ex, PMINIDUMP_USER_STREAM_INFORMATION usr, PMINIDUMP_CALLBACK_INFORMATION cb), (hp,pid,hf,type,ex,usr,cb), FALSE)
