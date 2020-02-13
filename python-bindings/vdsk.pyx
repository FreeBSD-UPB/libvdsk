from cvdsk cimport *
from libc.stdlib cimport malloc

cdef class vdsk:
    cdef vdskctx _c_vdsk

    def __cinit__(self, path, access):
        self._c_vdsk = vdsk_open(path, access, 0)
        if self._c_vdsk is NULL:
            raise MemoryError()

    def __dealloc__(self):
        if self._c_vdsk is not NULL:
            vdsk_close(self._c_vdsk)

    def open(self, bytes path, int access):
        if self._c_vdsk is not NULL:
            vdsk_close(self._c_vdsk)

        self._c_vdsk = vdsk_open(path, access, 0)

    def close(self):
        vdsk_close(self._c_vdsk)
        self._c_vdsk = NULL

    def read(self, bytes b, size, offset):
        cdef char *buf = b

        ret = vdsk_read(self._c_vdsk, buf, size, offset)

        return ret

    def write(self, bytes b, size, offset):
        cdef char *buf = b

        ret = vdsk_write(self._c_vdsk, <void *> buf, size, offset)

        return ret
