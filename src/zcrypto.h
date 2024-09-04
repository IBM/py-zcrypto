/*
 * © Copyright IBM Corporation 2024
 */

#ifndef __ZCRYPTO_H_
#define __ZCRYPTO_H_ 1
#define PY_SSIZE_T_CLEAN 

#include <gskcms.h>
#include <gskssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Python.h>
#include <errno.h>
#include <dynit.h>
#include <unistd.h>
#include <grp.h>

int createKDB_impl(const char* filename, const char* password, int length, int expiration, gsk_handle* handle);
int importKey_impl(const char* filename, const char* password, const char* label, gsk_handle* handle);
int exportKeyToFile_impl(const char* filename, const char* password, const char* label, gsk_handle* handle);
int exportCertToFile_impl(const char* filename, const char* label, gsk_handle* handle);
int exportKeyToBuffer_impl(const char* password, const char* label, gsk_buffer* stream, gsk_handle* handle);
int exportCertToBuffer_impl(const char* label, gsk_buffer* stream, gsk_handle* handle);
int openKDB_impl(const char* filename, const char* password, gsk_handle* handle);
int openKeyRing_impl(const char* ring_name, gsk_handle* handle);
int close_database_impl(gsk_handle* handle);
char* errorString_impl(int err, char *err_str, int err_strlen);

typedef struct zcrypto{
    PyObject_HEAD
    gsk_handle handle;
} zcrypto;

#endif
