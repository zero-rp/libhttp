#ifndef __SOCKET_H
#define __SOCKET_H

#include "config.h"
#include <stdint.h>

struct socket_server;

typedef void(__stdcall* socket_callback_dns)(struct socket_server * ss, void *ud, int state, char *ip);
typedef void(__stdcall* socket_callback_connect)(struct socket_server * ss, void *ud, int state, int fd);
typedef void(__stdcall* socket_callback_data)(struct socket_server * ss, void *ud, int state, char *data, uint32_t len);
typedef void(__stdcall* socket_callback_data_udp)(struct socket_server * ss, void *ud, int state, char *data, uint32_t len);
typedef void *(__stdcall* socket_callback_alloc)(struct socket_server * ss, size_t len);
typedef void(__stdcall* socket_callback_send)(struct socket_server * ss, void *ud);

#ifdef __cplusplus
extern "C" {
#endif

EXPORT int CALL socket_init();
EXPORT void CALL socket_uninit();

EXPORT struct socket_server * CALL socket_new();
EXPORT struct socket_server * CALL socket_default();
EXPORT void CALL socket_delete(struct socket_server *server);

//获取dns服务地址
EXPORT int CALL socket_getdnsip(uint32_t *list, int size);
//DNS解析
EXPORT void CALL socket_dns(struct socket_server * ss, char *name, socket_callback_dns cb, void *ud);
//连接服务器
EXPORT void CALL socket_tcp_connect(struct socket_server * ss, const char *host, int port, socket_callback_dns cb, void *ud);
//开始接受数据
EXPORT void CALL socket_tcp_start(struct socket_server *ss, int fd, socket_callback_alloc alloc_cb, socket_callback_data data_cb, void *ud);
//发送数据
EXPORT void CALL socket_tcp_send(struct socket_server *ss, int fd, void *buffer, int sz, socket_callback_send cb, void *ud);
//关闭连接
EXPORT void CALL socket_tcp_close(struct socket_server *ss, int fd);
//绑定UDP端口
EXPORT int CALL socket_udp_bind(struct socket_server * ss, const char *host, int port);
//开始接收UDP数据
EXPORT void CALL socket_udp_start(struct socket_server * ss, int fd, socket_callback_alloc alloc_cb, socket_callback_data_udp data_cb, void *ud);
//IOCP发送UDP数据包
EXPORT void CALL socket_udp_sendto(struct socket_server * ss, int fd, const char *host, int port, void *buffer, size_t len, socket_callback_send cb, void *ud);

#ifdef __cplusplus
}
#endif
#endif
