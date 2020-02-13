cdef extern from "../libvdsk/vdsk.h":
    ctypedef void *vdskctx
    ctypedef int off_t
    ctypedef struct iovec:
        pass

    void hello(const char *)
    vdskctx vdsk_open(const char *, int, size_t)
    int vdsk_close(vdskctx)

    int vdsk_fd(vdskctx)

    int vdsk_does_trim(vdskctx)

    off_t vdsk_media_size(vdskctx)
    int vdsk_sector_size(vdskctx)

    int vdsk_stripe_size(vdskctx)
    int vdsk_stripe_offset(vdskctx)

    ssize_t vdsk_read(vdskctx, void *, size_t, off_t)
    ssize_t vdsk_write(vdskctx, const void *, size_t, off_t)

    ssize_t vdsk_readv(vdskctx, const iovec *, int, off_t)
    ssize_t vdsk_writev(vdskctx, const iovec *, int, off_t)

    int vdsk_trim(vdskctx, off_t offset, size_t)
    int vdsk_flush(vdskctx)

