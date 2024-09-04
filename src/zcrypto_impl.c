/*
 * © Copyright IBM Corporation 2024
 */

#include "zcrypto.h"
#include <_Nascii.h>
#include <sys/stat.h>
#include <unistd.h>

extern PyObject * gsk_exception;

static int setfdccsid(int fd, unsigned short ccsid)
{
    attrib_t attr;
    memset(&attr, 0, sizeof(attr));
    attr.att_filetagchg = 1;
    attr.att_filetag.ft_ccsid = ccsid;
    return __fchattr(fd, &attr, sizeof(attr));
}

static char * convert_ascii_to_ebcdic(const char * ascii)
{
    int length = strlen(ascii) + 1;
    char * ebcdic = malloc(length);
    memcpy(ebcdic, ascii, length);
    __a2e_l(ebcdic, length);
    return ebcdic;
}

static char * convert_ebcdic_to_ascii(const char * ebcdic)
{
    int length = strlen(ebcdic) + 1;
    char * ascii = malloc(length);
    memcpy(ascii, ebcdic, length);
    __e2a_l(ascii, length);
    return ascii;
}

static void set_gsk_error(int rc)
{
    int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    const char * error_e = gsk_strerror(rc);
    __ae_thread_swapmode(orig);
    char * error_a = convert_ebcdic_to_ascii(error_e);

    PyObject * message = PyUnicode_DecodeLocale(error_a, "surrogateescape");
    PyObject * args = Py_BuildValue("(iO)", rc, message);

    Py_DECREF(message);
    
    PyErr_SetObject(gsk_exception, args);
}

static void write_stream_data(gsk_buffer * stream, const char * filename)
{
    FILE *fileptr;
    fileptr = fopen(filename, "wb");
    write(fileno(fileptr), stream->data, stream->length);
    fclose(fileptr);

    fileptr = fopen(filename, "a+");
    setfdccsid(fileno(fileptr), FT_BINARY);
    fclose(fileptr);
}

int createKDB_impl(const char* filename, const char* password, int length, int expiration, gsk_handle* handle)
{
    char * filename_e = convert_ascii_to_ebcdic(filename);
    char * password_e = convert_ascii_to_ebcdic(password);

    int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    int rc = gsk_create_database(filename_e, password_e, gskdb_dbtype_key, length, expiration, handle);
    __ae_thread_swapmode(orig);

    free(filename_e);
    free(password_e);

    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;
}

int exportKeyToFile_impl(const char* filename, const char* password, const char* label, gsk_handle* handle)
{
    char * password_e = convert_ascii_to_ebcdic(password);
    char * label_e = convert_ascii_to_ebcdic(label);
        
    gsk_buffer stream = {0,0};
    int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary, x509_alg_pbeWithSha1And3DesCbc, password_e, &stream);
    if (rc != 0) 
    {
        gsk_free_buffer(&stream); 
        free(password_e);
        free(label_e);
        set_gsk_error(rc);
        return -1;
    }

    write_stream_data(&stream, filename);

    gsk_free_buffer(&stream);
    free(password_e);
    free(label_e);
    return rc;
}

char* errorString_impl(int err, char *err_str, int err_strlen)
{
    int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    const char* errorStr_e = gsk_strerror(err);
    __ae_thread_swapmode(orig);
    strncpy(err_str, errorStr_e, err_strlen);
    __e2a_l(err_str, err_strlen);
    return err_str;
}

int openKDB_impl(const char* filename, const char* password, gsk_handle* handle)
{
    char * filename_e = convert_ascii_to_ebcdic(filename);
    char * password_e = convert_ascii_to_ebcdic(password);

    int num_records;
    gskdb_database_type type;

    int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    int rc = gsk_open_database(filename_e, password_e, 1, handle, &type, &num_records);
    __ae_thread_swapmode(orig);

    free(filename_e);
    free(password_e);

    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;
}

int openKeyRing_impl(const char* ring_name, gsk_handle* handle) 
{
    char * ring_name_e = convert_ascii_to_ebcdic(ring_name);

    int num_records;
    int orig = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    int rc = gsk_open_keyring(ring_name_e, handle, &num_records);
    __ae_thread_swapmode(orig);
    free(ring_name_e);
    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;
}

int exportCertToFile_impl(const char* filename, const char* label, gsk_handle* handle)
{
    char * label_e = convert_ascii_to_ebcdic(label);
    gsk_buffer stream = {0,0};

    int rc = gsk_export_certificate(*handle, label_e, gskdb_export_der_binary, &stream);
    if (rc != 0)
    {
        free(label_e);
        set_gsk_error(rc);
        return -1;
    }

    FILE *fileptr;
    fileptr = fopen(filename, "wb");
    write(fileno(fileptr), stream.data, stream.length);
    fclose(fileptr);

    fileptr = fopen(filename, "a+");
    setfdccsid(fileno(fileptr), FT_BINARY);
    fclose(fileptr);

    free(label_e);
    return rc;
}

int exportCertToBuffer_impl(const char* label, gsk_buffer* stream, gsk_handle* handle)
{
    char * label_e = convert_ascii_to_ebcdic(label);
    int rc = gsk_export_certificate(*handle, label_e, gskdb_export_der_binary, stream);
    free(label_e);
    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;    
}

int exportKeyToBuffer_impl(const char* password, const char* label, gsk_buffer* stream, gsk_handle* handle) 
{
    char * password_e = convert_ascii_to_ebcdic(password);
    char * label_e = convert_ascii_to_ebcdic(label);
    
    int rc = gsk_export_key(*handle, label_e, gskdb_export_pkcs12v3_binary, x509_alg_pbeWithSha1And3DesCbc, password_e, stream);
    free(password_e);
    free(label_e);
    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;
}

int importKey_impl(const char* filename, const char* password, const char* label, gsk_handle* handle) 
{
    FILE *fileptr;
    char * buffer;
    long filelen;

    char * filename_e = convert_ascii_to_ebcdic(filename);
    char * password_e = convert_ascii_to_ebcdic(password);
    char * label_e = convert_ascii_to_ebcdic(label);

    fileptr = fopen(filename, "rb");
    fseek(fileptr, 0, SEEK_END);
    filelen = ftell(fileptr);
    rewind(fileptr);

    buffer = (char *)malloc((filelen+1)*sizeof(char));
    fread(buffer, filelen, 1, fileptr);
    fclose(fileptr);

    gsk_buffer stream = {(unsigned int)((filelen+1)*sizeof(char)), (void*)buffer};
    int rc = gsk_import_key(*handle, label_e, password_e, &stream);
    free(filename_e);
    free(password_e);
    free(label_e);
    free(buffer);
    if (stream.data != buffer) 
    {
        gsk_free_buffer(&stream);
    }
    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;
}

int close_database_impl(gsk_handle* handle)
{
    int rc = gsk_close_database(handle);
    if (rc != 0) {
        set_gsk_error(rc);
        return -1;
    }
    return rc;
}
