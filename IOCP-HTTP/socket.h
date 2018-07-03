#ifndef __SOCKET_H
#define __SOCKET_H

#include "config.h"

struct socket_server;

typedef void(__stdcall* socket_callback_dns)(struct socket_server * ss, void *ud, int state, char *ip);
typedef void(__stdcall* socket_callback_connect)(struct socket_server * ss, void *ud, int state, int fd);
typedef void(__stdcall* socket_callback_data)(struct socket_server * ss, void *ud, int state, char *data, uint32_t len);
typedef void(__stdcall* socket_callback_free)(struct socket_server * ss, void *ud);

#ifdef __cplusplus
extern "C" {
#endif

EXPORT int CALL socket_init();
EXPORT void CALL socket_uninit();

EXPORT struct socket_server * CALL socket_new();
EXPORT void CALL socket_delete(struct socket_server *server);

//DNS解析
EXPORT void CALL socket_dns(struct socket_server * ss, char *name, socket_callback_dns cb, void *ud);
//连接服务器
EXPORT void CALL socket_tcp_connect(struct socket_server * ss, const char *host, int port, socket_callback_dns cb, void *ud);
//开始接受数据
EXPORT void CALL socket_tcp_start(struct socket_server *ss, int fd, socket_callback_data cb, void *ud);
//发送数据
EXPORT void CALL socket_tcp_send(struct socket_server *ss, int fd, void *buffer, int sz, socket_callback_free cb, void *ud);

#ifdef __cplusplus
}
#endif
#endif
