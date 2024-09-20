#include "native.h"
#include <android/log.h>
#include <jni.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

#ifndef LOG_TAG
#define LOG_TAG "lsp-entry"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

//////////////////////
static NativeAPIEntries *gHandler = nullptr;

#define HOOK_SYMBOL(handle, func) \
    hook_function(handle, #func, (void *)new_##func, (void **)&orig_##func)
#define HOOK_DEF(ret, func, ...)     \
    ret (*orig_##func)(__VA_ARGS__); \
    ret new_##func(__VA_ARGS__)

static inline void hook_function(
        void *handle,
        const char *symbol,
        void *new_func,
        void **old_func) {
    void *addr = nullptr;

//    if (gHandler) {
//        addr = gHandler->symbolResolverFunc(NULL, symbol);
//    } else {
//        addr = dlsym(handle, symbol);
//    }
    addr = dlsym(handle, symbol);
    if (addr == nullptr) {
        LOG("Not found symbol : %s", symbol);
        return;
    }
    if (gHandler) {
        LOG("hook_func %s addr %p", symbol, addr);
        gHandler->hook_func(addr, new_func, old_func);
    }
}

HOOK_DEF(int, __system_property_get, const char *key, const char *value) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    dladdr((void *)value, &info);
    LOG("__system_property_get() key = %s called from: %s (%s)", key, info.dli_fname, info.dli_sname);
    return orig___system_property_get(key, value);
}

HOOK_DEF(int, __system_property_find, const char *key) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    dladdr((void *)key, &info);
    LOG("__system_property_find() key = %s called from: %s (%s)", key, info.dli_fname, info.dli_sname);
    return orig___system_property_find(key);
}


typedef int (*callback) (struct dl_phdr_info *info,
                         size_t size, void *data);
HOOK_DEF(int, dl_iterate_phdr, callback cb, void * data) {
    LOG("dl_iterate_phdr cb %p", cb);
    //sleep(31536000);
    return orig_dl_iterate_phdr(cb, data);
}

//int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
//                   void *(*start_routine) (void *), void *arg);


void *stub_rountine(void *unused) {
    LOG("stub_rountine() called!");

    sleep(31536000);
    return nullptr;
}

HOOK_DEF(int, pthread_create, pthread_t *thread, const pthread_attr_t *attr,
         void *(*start_routine) (void *), void *arg) {

    Dl_info info;
    memset(&info, 0, sizeof(info));
    dladdr((void *)start_routine, &info);

    if (strstr(info.dli_fname, "libNetHTProtect")) {
        LOG("Block pthread_create start_routine %p, called from: %s (%s) ", start_routine, info.dli_fname, info.dli_sname);
        return orig_pthread_create(thread, attr, stub_rountine, arg);
    }

    LOG("pthread_create start_routine %p, called from: %s (%s) ", start_routine, info.dli_fname, info.dli_sname);
    return orig_pthread_create(thread, attr, start_routine, arg);
}


HOOK_DEF(void *, dlsym, void * handler, const char * symbol) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    dladdr((void *)symbol, &info);

    if (info.dli_fname != nullptr &&
            (strstr(info.dli_fname,"libunity")
            || strstr("libil2cpp",info.dli_fname)
            || strstr(info.dli_fname,"libtolua"))) {
        LOG("dlsym() skip %s", info.dli_fname);
        return orig_dlsym(handler, symbol);
    }

    LOG("dlsym() symbol = %s called from: %s (%s)", symbol, info.dli_fname, info.dli_sname);

    int ret = 0;
    void * sym_addr = orig_dlsym(handler, symbol);
    if (symbol != nullptr &&
            strstr("dl_iterate_phdr", symbol)) {
        ret = gHandler->hook_func(sym_addr, (void *)(new_dl_iterate_phdr),
                            (void **)(&orig_dl_iterate_phdr));

        LOG("Hook dlsym() %s return %p %d", symbol, sym_addr, ret);

    } else if (symbol != nullptr && strstr("pthread_create", symbol)) {
        ret = gHandler->hook_func(sym_addr, (void *)(new_pthread_create),
                            (void **)(&orig_pthread_create));

        LOG("Hook dlsym() %s return %p %d", symbol, sym_addr, ret);
    }

    return sym_addr;
}

//        int kill(pid_t pid, int sig);
HOOK_DEF(int, kill, pid_t pid, int sig) {
    LOG("Kill %d sig %d" , pid, sig);
    return orig_kill(pid, sig);
}

//         void _exit(int status);
HOOK_DEF(void, _exit,int status) {
    LOG("_exit %d " , status);
    return orig__exit(status);
}

// typedef long (*ptrace_func)(int, ...);
HOOK_DEF(long, __ptrace, int req, pid_t pid, void *addr, void *data) {
    LOG("ptrace req %d pid %d" , req, pid);
    return orig___ptrace(req, pid, addr, data);
}
///////////////////////////////////////////////////////////////////////


FILE *(*original_fopen)(const char *filename, const char *mode);
FILE *fake_fopen(const char *filename, const char *mode) {
    LOG("fopen hook %s", filename);
    return original_fopen(filename, mode);
}

int (*backup_faccessat)(int dirfd, const char *pathname, int mode, int flags);
int fake_faccessat(int dirfd, const char *pathname, int mode, int flags){
    LOG("faccessat hookd %s", pathname);
    return backup_faccessat(dirfd, pathname, mode, flags);
}

///////////////////////////////////////////////////////////////////////


jclass (*backup_FindClass)(JNIEnv *env, const char *name);
jclass fake_FindClass(JNIEnv *env, const char *name) {
    LOG("FindClass %s", name);
    return backup_FindClass(env, name);
}

void on_library_loaded(const char *name, void *handle) {
    // hooks on `libtarget.so`
    LOG("on_library_loaded %s", name);
//    if (strcmp("libtarget.so", name) == 0) {
//        void *target = dlsym(handle, "target_fun");
//        hook_func(target, (void *) fake, (void **) &backup);
//    }

//    if (strcmp(name, "liblog")) {
//        HOOK_SYMBOL(nullptr, __system_property_find);
//    }
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    LOG("native_init");
    gHandler = const_cast<NativeAPIEntries *>(entries);
    // HOOK_SYMBOL(nullptr, kill);
    // HOOK_SYMBOL(nullptr, _exit);

    // HOOK_SYMBOL(nullptr, __ptrace);

    // HOOK_SYMBOL(nullptr, __system_property_get);
    // HOOK_SYMBOL(nullptr, dlsym);

    //gHandler->hook_func((void *) fopen, (void *) fake_fopen, (void **) &original_fopen);
    // system hooks
    // hook_func((void*) faccessat, (void*) fake_faccessat, (void**) &backup_fopen);

    return on_library_loaded;
}


jboolean entry_native_init(JNIEnv *env, jclass clazz, jint flags) {
    LOG("demo_native_init() flags = 0x%x, gHandler = %p", flags, gHandler);
    return JNI_TRUE;
}

jboolean entry_native_deInit(JNIEnv *env, jclass clazz, jint flags) {
    LOG("demo_native_deInit() flags = 0x%x", flags);
    return JNI_TRUE;
}

static JNINativeMethod jniMain[] = {
        {"initNative", "(I)Z", (void *)entry_native_init},
        {"deInitNative", "(I)Z", (void *)entry_native_deInit}};


static int registerNativeMethods(
        JNIEnv *env,
        const char *className,
        JNINativeMethod *jniMethods,
        int methods) {
    jclass clazz = env->FindClass(className);
    if (clazz == NULL) {
        LOGE("registerNativeMethods() error!");
        return 0;
    }
    return env->RegisterNatives(clazz, jniMethods, methods) >= 0;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
jint JNI_OnLoad(JavaVM *jvm, void*) {
    LOG("JNI_OnLoad");
    JNIEnv *env = nullptr;
    jvm->GetEnv((void **)&env, JNI_VERSION_1_6);
    if (gHandler) {
	    // gHandler->hook_func((void *)env->functions->FindClass, (void *)fake_FindClass, (void **)&backup_FindClass);
        // HOOK_SYMBOL(nullptr, __system_property_get);
        gHandler->hook_func((void*) faccessat, (void*) fake_faccessat, (void**) &backup_faccessat);
    }

    int jniMethodSize = sizeof(JNINativeMethod);
    if (!registerNativeMethods(
                env, "com/android/hp/Entry", jniMain, sizeof(jniMain) / jniMethodSize)) {
        LOGE("JNI Loaded register main error!");
        return JNI_ERR;
    }
	return JNI_VERSION_1_6;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
void JNI_OnUnload(JavaVM *vm, void *reserved) {
    LOG("JNI_OnUnload()");
}


