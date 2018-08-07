#ifndef __HTTP_H_
#define __HTTP_H_

#include "config.h"

struct http_request;

//HTTP回调
typedef void(__stdcall* http_callback_end)(struct http_request *request, void *ud, int state);
typedef void(__stdcall* http_callback_header)(struct http_request *request, void *ud, char *k, char *v);
typedef void(__stdcall* http_callback_body)(struct http_request *request, void *ud, char *data, int len);

#ifdef __cplusplus
extern "C" {
#endif
//HTTP初始化
EXPORT int CALL HTTP_Init();
//HTTP反初始化
EXPORT void CALL HTTP_UnInit();
//创建HTTP请求
EXPORT struct http_request * CALL HTTP_Request_New(http_callback_end cb_end, http_callback_body cb_body, http_callback_header cb_header, void *ud);
//销毁请求
EXPORT struct http_request * CALL HTTP_Request_Delete(struct http_request *request);
//调整选项
EXPORT void CALL HTTP_Request_Option(struct http_request *request, char *k, char *v);
//设置请求头
EXPORT void CALL HTTP_Request_SetHeader(struct http_request *request, char *k, char *v);
//打开请求
EXPORT void CALL HTTP_Request_Open(struct http_request *request, char * method, char * url);
//发送请求
EXPORT void CALL HTTP_Request_Send(struct http_request *request);

//获取状态码
EXPORT int CALL HTTP_Request_Status(struct http_request *request);
#ifdef __cplusplus
}
#endif
#endif
