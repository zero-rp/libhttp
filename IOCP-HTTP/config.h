#ifndef __CONFIG_H__
#define __CONFIG_H__


#ifdef PLATFORM_OS_WIN
# if defined(BUILDING_SHARED)
//编译成动态库
#ifdef __cplusplus
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT __declspec(dllexport)
#endif
#define CALL __stdcall
# elif defined(USING_SHARED)
//使用动态库
#ifdef __cplusplus
#define EXPORT extern "C" __declspec(dllimport)
#else
#define EXPORT __declspec(dllimport)
#endif
#define CALL __stdcall 
# else
//编译成静态库
#ifdef __cplusplus
#define EXPORT extern "C"
#else
#define EXPORT 
#endif
#define CALL 
# endif
#else
#ifdef __cplusplus
#define EXPORT extern "C" 
#else
#define EXPORT
#endif
#define CALL __attribute__((__stdcall__))
#endif

#endif /* !__URI_H__ */