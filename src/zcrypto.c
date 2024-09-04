/*
 * © Copyright IBM Corporation 2024
 */

#include "zcrypto.h"
#include "structmember.h"

PyObject * gsk_exception = NULL;

static void zcrypto_dealloc(zcrypto* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject * zcrypto_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    zcrypto *self = (zcrypto *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}

static int zcrypto_init(zcrypto *self, PyObject *args, PyObject *kwds)
{
    self->handle = NULL;             
    return 1;
}

static PyObject* open_key_ring(zcrypto* self, PyObject* args)
{
    char *ring_name = NULL;

    if (!PyArg_ParseTuple(args, "s", &ring_name))
    {
        PyErr_SetString(PyExc_RuntimeError, "open_key_ring needs 1 argument");
        return NULL;
    }

    int rc = openKeyRing_impl(ring_name, &(self->handle));
    if (rc == -1) {
        return NULL;
    }
    return PyLong_FromLong(rc);
}

static PyObject *close_database(zcrypto* self, PyObject *args)
{
    int rc = close_database_impl(&(self->handle));
    if (rc == -1) {
        return NULL;
    }
    return PyLong_FromLong(rc);
}

static PyObject *create_KDB(zcrypto* self, PyObject *args)
{
    char *filename, *password = NULL;
    int length, expiration = 0;

    if (!PyArg_ParseTuple(args, "ssii", &filename, &password, &length, &expiration))
    {
        PyErr_SetString(PyExc_RuntimeError, "create_KDB needs 4 arguments");
        return NULL;
    }

    int rc = createKDB_impl(filename, password, length, expiration, &(self->handle));
    if (rc == -1) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *export_key_to_file(zcrypto* self, PyObject *args)
{
    char *filename, *password, *label = NULL;

    if (!PyArg_ParseTuple(args, "sss", &filename, &password, &label))
    {
        PyErr_SetString(PyExc_RuntimeError, "export_key_to_file needs 3 arguments");
        return NULL;
    }

    int rc = exportKeyToFile_impl(filename, password, label, &(self->handle));
    if (rc == -1) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *export_cert_to_file(zcrypto* self, PyObject *args)
{
    char *filename, *label = NULL;

    if (!PyArg_ParseTuple(args, "ss", &filename, &label))
    {
        PyErr_SetString(PyExc_RuntimeError, "export_cert_to_file needs 2 arguments");
        return PyLong_FromLong(-1);
    }

    int rc = exportCertToFile_impl(filename, label, &(self->handle));
    if (rc == -1) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *open_KDB(zcrypto *self, PyObject *args)
{
    char *database, *password = NULL;

    if (!PyArg_ParseTuple(args, "ss", &database, &password))
    {
        PyErr_SetString(PyExc_RuntimeError, "open_KDB needs 2 arguments");
        return NULL;
    }

    int rc = openKDB_impl(database, password, &(self->handle));
    if (rc == -1) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *import_key(zcrypto *self, PyObject *args)
{
    char * filename, *password, *label = NULL;

    if (!PyArg_ParseTuple(args, "sss", &filename, &password, &label))
    {
        PyErr_SetString(PyExc_RuntimeError, "import_key needs 3 string arguments");
        return NULL;
    }

    int rc = importKey_impl(filename, password, label, &(self->handle));
    if (rc == -1) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *export_key_to_buffer(zcrypto *self, PyObject *args)
{
    char * password, *label = NULL;
    gsk_buffer stream = {0,0};

    if (!PyArg_ParseTuple(args, "ss", &password, &label))
    {
        PyErr_SetString(PyExc_RuntimeError, "export_key_to_buffer needs 2 string arguments");
        return NULL;
    }

    int rc = exportKeyToBuffer_impl(password, label, &stream, &(self->handle));
    if (rc == -1) {
        gsk_free_buffer(&stream);
        return NULL;
    }
    
    PyObject *py_list = PyList_New(stream.length);
    Py_ssize_t i = 0;

    for (i = 0; i < stream.length; i++)
    {
        PyObject *item = PyLong_FromLong(((char*)stream.data)[i]);
        PyList_SetItem(py_list, i, item);
    }
    
    if (PyList_Check(py_list)!= 1)
    {
        Py_XDECREF(py_list);
        py_list = NULL;
        PyErr_SetString(PyExc_RuntimeError, "Could not form Python list.");
        return NULL;        
    }

    return py_list;
}

static PyObject *export_cert_to_buffer(zcrypto *self, PyObject *args)
{
    char *label = NULL;
    gsk_buffer stream = {0,0};

    if (!PyArg_ParseTuple(args, "s", &label))
    {
        PyErr_SetString(PyExc_RuntimeError, "export_cert_to_buffer needs 1 string argument");
        return NULL;
    }

    int rc = exportCertToBuffer_impl(label, &stream, &(self->handle));
    if (rc == -1)
    {
        gsk_free_buffer(&stream);
        return NULL;
    }

    PyObject *py_list = PyList_New(stream.length);
    Py_ssize_t i = 0;

    for (i = 0; i < stream.length; i++)
    {
        PyObject *item = PyLong_FromLong(((char*)stream.data)[i]);
        PyList_SetItem(py_list, i, item);
    }

    if (PyList_Check(py_list) != 1)
    {
        Py_XDECREF(py_list);
        py_list = NULL;
        PyErr_SetString(PyExc_RuntimeError, "Could not form Python list.");
        return NULL;        
    }

    return py_list;
}

static PyObject *get_error_string(zcrypto *self, PyObject *args)
{
    int err = 0;
    char err_str[256];
    if (!PyArg_ParseTuple(args, "i", &err))
    {
        PyErr_SetString(PyExc_RuntimeError,"get_error_string needs 1 int argument");
        return NULL;    
    }

    return Py_BuildValue("s", errorString_impl(err, err_str, sizeof(err_str)));
}


static PyMemberDef zcrypto_members[] = 
{
    //Type is object, offset is to access the handle in struct,
    //0 is a flag making the field read/writeable.
    {"handle", T_OBJECT, offsetof(zcrypto, handle), 0, "zcrypto handle"},
    {NULL}
};

static PyMethodDef zcrypto_methods[] = 
{
    {"open_key_ring", (PyCFunction)open_key_ring, METH_VARARGS,
    "Opens a SAF digital certificate key ring or z/OS PKCS #11 token.\n\
    Parameters:\n\tring_name -- specifies the SAF key ring or z/OS PKCS #11 token name.\n\
    Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"create_KDB", (PyCFunction)create_KDB, METH_VARARGS,
    "Creates a key or request database.\n\
    Parameters:\n\tfilename -- specifies database filename, cannot exceed 251 chars.\n\tpassword -- database password.\n\
    \trecord_length -- specifies database record length, minimum 2500 default 5000.\n\tpwd_expiration -- password expiration time as the number of seconds since the POSIX epoch. 0 means the password does not expire.\n\
    Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"open_KDB", (PyCFunction)open_KDB, METH_VARARGS,
    "Opens a key or request database.\n\
    Parameters:\n\tfilename -- specifies database filename, cannot exceed 251 chars.\n\tpassword -- database password.\n\
    Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"export_key_to_file", (PyCFunction)export_key_to_file, METH_VARARGS,
    "Exports a certificate and the associated private key to a file.\n\
    Parameters:\n\tfilename -- file that the key will be exported to\n\tpassword -- password for exported file\n\
    \tlabel -- specifies the label for the database record.\n\
    Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"export_cert_to_file", (PyCFunction)export_cert_to_file, METH_VARARGS,
     "Exports a certificate to a file.\n\
     Parameters:\n\tfilename -- file that the cert will be exported to\n\
     \tlabel -- specifies the label for the database record.\n\
     Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"import_key", (PyCFunction)import_key, METH_VARARGS,
    "Imports a certificate and associated private key.\n\
    Parameters:\n\tfilename -- file that the key will be imported from\n\tpassword -- password for imported file\n\
    \tlabel -- specifies the label for the new database record.\n\
    Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"export_key_to_buffer",(PyCFunction)export_key_to_buffer, METH_VARARGS,
    "Exports a certificate and the associated private key to a buffer.\n\
    Parameters:\n\tpassword -- password for exported file.\n\tlabel -- specifies the label for the database record.\n\
    Returns:\n\tReturn the byte stream for the encoded certificate.\n\
    "},
    {"export_cert_to_buffer", (PyCFunction)export_cert_to_buffer, METH_VARARGS,
    "Exports a certificate to a buffer.\n\
    Parameters:\n\tlabel -- specifies the label for the database record.\n\
    Returns:\n\tReturn the byte stream for the encoded certificate.\n\
    "},
    {"close_database", (PyCFunction)close_database, METH_VARARGS,
    "Closes a key or request database.\n\
    Returns:\n\tNone. Throws GSKError on error.\n\
    "},
    {"get_error_string", (PyCFunction)get_error_string, METH_VARARGS,
    "Returns an error string.\n\
    Parameters:\n\terror -- specifies integer error number.\n\
    Returns:\n\tString error value.\n\
    "},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef Python_zcrypto_module= 
{
    PyModuleDef_HEAD_INIT,
    "py_zcrypto",
    "Python interface for RACF Key Rings & Key Databases on z/OS",
    -1,
    zcrypto_methods
};

static PyTypeObject zcrypto_type = 
{
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "py_zcrypto.zcrypto",
    .tp_basicsize = sizeof(zcrypto),
    .tp_new = zcrypto_new,
    .tp_dealloc = (destructor)zcrypto_dealloc,
    .tp_methods = zcrypto_methods,
    .tp_members = zcrypto_members,
    .tp_init = (initproc)zcrypto_init,
};

PyMODINIT_FUNC PyInit_py_zcrypto()
{
    PyObject* m;

    zcrypto_type.tp_new = PyType_GenericNew;
    if (PyType_Ready(&zcrypto_type) < 0)
    {
        return NULL;
    }

    m = PyModule_Create(&Python_zcrypto_module);
    if (m == NULL)
    {
        return NULL;
    }

    gsk_exception = PyErr_NewException("py_zcrypto.GSKError", PyExc_OSError, NULL);
    PyModule_AddObject(m, "GSKError", gsk_exception);

    Py_INCREF(&zcrypto_type);
    PyModule_AddObject(m, "zcrypto", (PyObject *)&zcrypto_type);
    PyModule_SetDocString(m, "Python module to access RACF methods.");
    return m;
}


