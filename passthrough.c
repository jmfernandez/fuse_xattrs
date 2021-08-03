/*
  fuse_xattrs - Add xattrs support using sidecar files

  Copyright (C) 2016-2017  Felipe Barriga Richards <felipe {at} felipebarriga.cl>

  Based on passthrough.c (libfuse example)

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#define FUSE_USE_VERSION 31

/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700

#include <fuse.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/xattr.h>
#include <sys/file.h> /* flock(2) */

#include "fuse_xattrs_config.h"
#ifdef HAVE_UTIMENSAT
#   include <fcntl.h>
#   include <sys/stat.h>
#endif

#include "xattrs_config.h"
#include "binary_storage.h"

#include "utils.h"

static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;
	cfg->nullpath_ok = 1;

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}


static int chown_new_file(const char * path, struct fuse_context *fc) {
    return lchown(path, fc->uid, fc->gid);
}

static int xmp_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    int res;
    char *_path;

    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

	if(fi)
		res = fstat(fi->fh, stbuf);
	else
        _path = prepend_source_directory(path);
        res = lstat(_path, stbuf);
        free(_path);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    res = access(_path, mask);
    free(_path);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    res = readlink(_path, buf, size - 1);
    free(_path);

    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}

struct xmp_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static int xmp_opendir(const char *path, struct fuse_file_info *fi)
{
	int res;
	struct xmp_dirp *d = malloc(sizeof(struct xmp_dirp));
	if (d == NULL)
		return -ENOMEM;

    if (fi != NULL && fi->fh != 0) {
        d->dp = fdopendir(fi->fh);
    } else {
        char *_path = prepend_source_directory(path);
        d->dp = opendir(_path);
        free(_path);
    }
	if (d->dp == NULL) {
		res = -errno;
		free(d);
		return res;
	}
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (unsigned long) d;
	return 0;
}

static inline struct xmp_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct xmp_dirp *) (uintptr_t) fi->fh;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi,
		       enum fuse_readdir_flags flags)
{
	struct xmp_dirp *d = get_dirp(fi);

	(void) path;
	if (offset != d->offset) {
#ifndef __FreeBSD__
		seekdir(d->dp, offset);
#else
		/* Subtract the one that we add when calling
		   telldir() below */
		seekdir(d->dp, offset-1);
#endif
		d->entry = NULL;
		d->offset = offset;
	}
	while (1) {
		struct stat st;
		off_t nextoff;
		enum fuse_fill_dir_flags fill_flags = 0;
        int read_entry = 1;

		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry)
				break;
		}
        
        if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(d->entry->d_name) == 1) {
            read_entry = 0;
        }
        
        if (read_entry != 0) {
#ifdef HAVE_FSTATAT
            if (flags & FUSE_READDIR_PLUS) {
                int res;

                res = fstatat(dirfd(d->dp), d->entry->d_name, &st,
                          AT_SYMLINK_NOFOLLOW);
                if (res != -1)
                    fill_flags |= FUSE_FILL_DIR_PLUS;
            }
#endif
            if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
                memset(&st, 0, sizeof(st));
                st.st_ino = d->entry->d_ino;
                st.st_mode = d->entry->d_type << 12;
            }
        }
        
        nextoff = telldir(d->dp);
#ifdef __FreeBSD__		
		/* Under FreeBSD, telldir() may return 0 the first time
		   it is called. But for libfuse, an offset of zero
		   means that offsets are not supported, so we shift
		   everything by one. */
		nextoff++;
#endif
        if (read_entry != 0) {
            if (filler(buf, d->entry->d_name, &st, nextoff, fill_flags))
                break;
        }

		d->entry = NULL;
		d->offset = nextoff;
	}

	return 0;
}

static int xmp_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct xmp_dirp *d = get_dirp(fi);
	(void) path;
	closedir(d->dp);
	free(d);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(_path, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(_path, mode);
    else
        res = mknod(_path, mode, rdev);

    free(_path);
    if (res == -1) {
        res = -errno;
    }

    return res;
}

static int xmp_mkdir(const char *path, mode_t mode) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    res = mkdir(_path, mode);

    if (res == -1) {
        free(_path);
        return -errno;
    }
    
    struct fuse_context *fc = fuse_get_context();
    res = chown_new_file(_path, fc);
    free(_path);
    
    return res;
}

static int xmp_unlink(const char *path) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    res = unlink(_path);

    if (res == -1) {
        free(_path);
        return -errno;
    }

    char *sidecar_path = get_sidecar_path(_path);
    if (is_regular_file(sidecar_path)) {
        if (unlink(sidecar_path) == -1) {
            error_print("Error removing sidecar file: %s\n", sidecar_path);
        }
    }
    free(sidecar_path);
    free(_path);

    return 0;
}

// FIXME: remove sidecar??
static int xmp_rmdir(const char *path) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    res = rmdir(_path);
    if (res == -1) {
        free(_path);
        return -errno;
    }

    char *sidecar_path = get_sidecar_path(_path);
    if (is_regular_file(sidecar_path)) {
        if (unlink(sidecar_path) == -1) {
            error_print("Error removing sidecar file: %s\n", sidecar_path);
        }
    }
    free(sidecar_path);
    free(_path);

    return 0;
}

static int xmp_symlink(const char *from, const char *to) {
    int res;
    if (xattrs_config.show_sidecar == 0) {
        if (filename_is_sidecar(from) == 1 || filename_is_sidecar(to)) {
            return -ENOENT;
        }
    }

    char *_to = prepend_source_directory(to);
    res = symlink(from, _to);

    if (res == -1) {
        free(_to);
        return -errno;
    }
    
    struct fuse_context *fc = fuse_get_context();
    res = chown_new_file(_to, fc);
    free(_to);
    
    return res;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags) {
    int res;
    
    if (xattrs_config.show_sidecar == 0) {
        if (filename_is_sidecar(from) == 1 || filename_is_sidecar(to)) {
            return -ENOENT;
        }
    }
    
	/* When we have renameat2() in libc, then we can implement flags */
	if (flags)
		return -EINVAL;
    
    char *_from = prepend_source_directory(from);
    char *_to = prepend_source_directory(to);
    res = rename(_from, _to);

    if (res == -1) {
        free(_from);
        free(_to);
        return -errno;
    }

    char *from_sidecar_path = get_sidecar_path(_from);
    char *to_sidecar_path = get_sidecar_path(_to);

    // FIXME: Remove to_sidecar_path if it exists ?
    if (is_regular_file(from_sidecar_path)) {
        if (rename(from_sidecar_path, to_sidecar_path) == -1) {
            error_print("Error renaming sidecar. from: %s to: %s\n", from_sidecar_path, to_sidecar_path);
        }
    }
    free(from_sidecar_path);
    free(to_sidecar_path);

    free(_from);
    free(_to);

    return 0;
}

// TODO: handle sidecar file ???
static int xmp_link(const char *from, const char *to) {
    int res;
    if (xattrs_config.show_sidecar == 0) {
        if (filename_is_sidecar(from) == 1 || filename_is_sidecar(to)) {
            return -ENOENT;
        }
    }

    char *_from = prepend_source_directory(from);
    char *_to = prepend_source_directory(to);
    res = link(_from, _to);
    if (res == 0) {
        char *sidecar_from = get_sidecar_path(_from);
        if (is_regular_file(sidecar_from)) {
            char *sidecar_to = get_sidecar_path(_to);
            if (is_regular_file(sidecar_to)) {
                if (unlink(sidecar_to) == -1) {
                    error_print("Error removing sidecar file: %s\n", sidecar_to);
                }
            }
            res = link(sidecar_from, sidecar_to);
            if (res == -1) {
                res = -errno;
            }
            free(sidecar_to);
        }
        free(sidecar_from);
    }
    
    if (res == -1) {
        res = -errno;
    }
        
    free(_from);
    free(_to);

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

 	if(fi) {
		res = fchmod(fi->fh, mode);
	} else {
        char *_path = prepend_source_directory(path);
        res = chmod(_path, mode);
        free(_path);
    }

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

	if (fi) {
		res = fchown(fi->fh, uid, gid);
    } else {
        char *_path = prepend_source_directory(path);
        res = lchown(_path, uid, gid);
        free(_path);
    }

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

	if(fi) {
		res = ftruncate(fi->fh, size);
    } else {
        char *_path = prepend_source_directory(path);
        res = truncate(_path, size);
        free(_path);
    }

    if (res == -1)
        return -errno;

    return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    int res;

	/* don't use utime/utimes since they follow symlinks */
	if (fi) {
		res = futimens(fi->fh, ts);
    } else {
        char *_path = prepend_source_directory(path);
        res = utimensat(0, _path, ts, AT_SYMLINK_NOFOLLOW);
        free(_path);
    }
    if (res == -1)
        return -errno;

    return 0;
}
#endif

static int xmp_open(const char *path, struct fuse_file_info *fi) {
    int fd;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    fd = open(_path, fi->flags);
    free(_path);

    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int res;
    
    char *_path = prepend_source_directory(path);
    int fd = open(_path, fi->flags, mode);
    if (fd == -1) {
        free(_path);
        return -errno;
    }

    struct fuse_context *fc = fuse_get_context();
    res = chown_new_file(_path, fc);
    free(_path);

    fi->fh = fd;

    return res;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi)
{
    (void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

    int res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_read_buf(const char *path, struct fuse_bufvec **bufp,
			size_t size, off_t offset, struct fuse_file_info *fi)
{
	struct fuse_bufvec *src;

	(void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

	src = malloc(sizeof(struct fuse_bufvec));
	if (src == NULL)
		return -ENOMEM;

	*src = FUSE_BUFVEC_INIT(size);

	src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	src->buf[0].fd = fi->fh;
	src->buf[0].pos = offset;

	*bufp = src;

	return 0;
}

static int xmp_write(const char *path, const char *buf, size_t size,
              off_t offset, struct fuse_file_info *fi)
{
    (void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

static int xmp_write_buf(const char *path, struct fuse_bufvec *buf,
		     off_t offset, struct fuse_file_info *fi)
{
	(void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }
	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = offset;

	return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int xmp_statfs(const char *path, struct statvfs *stbuf) {
    int res;
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    char *_path = prepend_source_directory(path);
    res = statvfs(_path, stbuf);
    free(_path);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_flush(const char *path, struct fuse_file_info *fi)
{
	int res;

	(void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }
	/* This is called from every close on an open file, so call the
	   close on the underlying filesystem.	But since flush may be
	   called multiple times for an open file, this must not really
	   close the file.  This is important if used on a network
	   filesystem like NFS which flush the data/metadata on close() */
	res = close(dup(fi->fh));
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }
    return close(fi->fh);
}

static int xmp_fsync(const char *path, int isdatasync,
              struct fuse_file_info *fi) {
	int res;
	(void) path;

    if (fi == NULL || fi->fh == 0) {
        return -1;
    }
#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
		res = fsync(fi->fh);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
                  off_t offset, off_t length, struct fuse_file_info *fi)
{
    (void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

    int res;
    if (mode)
        return -EOPNOTSUPP;

    return -posix_fallocate(fi->fh, offset, length);
}
#endif

#ifdef HAVE_LIBULOCKMGR
static int xmp_lock(const char *path, struct fuse_file_info *fi, int cmd,
		    struct flock *lock)
{
	(void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

	return ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner,
			   sizeof(fi->lock_owner));
}
#endif

static int xmp_flock(const char *path, struct fuse_file_info *fi, int op)
{
	int res;
	(void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

	res = flock(fi->fh, op);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t xmp_copy_file_range(const char *path_in,
				   struct fuse_file_info *fi_in,
				   off_t off_in, const char *path_out,
				   struct fuse_file_info *fi_out,
				   off_t off_out, size_t len, int flags)
{
	ssize_t res;
	(void) path_in;
	(void) path_out;
    if (fi_in == NULL || fi_in->fh == 0 || fi_out == NULL || fi_out->fh == 0) {
        return -1;
    }

	res = copy_file_range(fi_in->fh, &off_in, fi_out->fh, &off_out, len,
			      flags);
	if (res == -1)
		return -errno;

	return res;
}
#endif

static off_t xmp_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
	off_t res;
	(void) path;
    if (fi == NULL || fi->fh == 0) {
        return -1;
    }

	res = lseek(fi->fh, off, whence);
	if (res == -1)
		return -errno;

	return res;
}

static int sidecar_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    if (get_namespace(name) != USER) {
        debug_print("Only user namespace is supported. name=%s\n", name);
        return -ENOTSUP;
    }
    if (strlen(name) > XATTR_NAME_MAX) {
        debug_print("attribute name must be equal or smaller than %d bytes\n", XATTR_NAME_MAX);
        return -ERANGE;
    }
    if (size > XATTR_SIZE_MAX) {
        debug_print("attribute value cannot be bigger than %d bytes\n", XATTR_SIZE_MAX);
        return -ENOSPC;
    }

    char *_path = prepend_source_directory(path);

#ifdef DEBUG
    char *sanitized_value = sanitize_value(value, size);
    debug_print("path=%s name=%s value=%s size=%zu XATTR_CREATE=%d XATTR_REPLACE=%d\n",
                _path, name, sanitized_value, size, flags & XATTR_CREATE, flags & XATTR_REPLACE);

    free(sanitized_value);
#endif

    int rtval = binary_storage_write_key(_path, name, value, size, flags);
    free(_path);

    return rtval;
}

static int sidecar_getxattr(const char *path, const char *name, char *value, size_t size)
{
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    if (get_namespace(name) != USER) {
        debug_print("Only user namespace is supported. name=%s\n", name);
        return -ENOTSUP;
    }
    if (strlen(name) > XATTR_NAME_MAX) {
        debug_print("attribute name must be equal or smaller than %d bytes\n", XATTR_NAME_MAX);
        return -ERANGE;
    }

    char *_path = prepend_source_directory(path);
    debug_print("path=%s name=%s size=%zu\n", _path, name, size);
    int rtval = binary_storage_read_key(_path, name, value, size);
    free(_path);

    return rtval;
}

static int sidecar_listxattr(const char *path, char *list, size_t size)
{
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    if (size > XATTR_LIST_MAX) {
        debug_print("The size of the list of attribute names for this file exceeds the system-imposed limit.\n");
        return -E2BIG;
    }

    char *_path = prepend_source_directory(path);
    debug_print("path=%s size=%zu\n", _path, size);
    int rtval = binary_storage_list_keys(_path, list, size);
    free(_path);

    return rtval;
}

static int sidecar_removexattr(const char *path, const char *name)
{
    if (xattrs_config.show_sidecar == 0 && filename_is_sidecar(path) == 1)  {
        return -ENOENT;
    }

    if (get_namespace(name) != USER) {
        debug_print("Only user namespace is supported. name=%s\n", name);
        return -ENOTSUP;
    }
    if (strlen(name) > XATTR_NAME_MAX) {
        debug_print("attribute name must be equal or smaller than %d bytes\n", XATTR_NAME_MAX);
        return -ERANGE;
    }

    char *_path = prepend_source_directory(path);
    debug_print("path=%s name=%s\n", _path, name);
    int rtval = binary_storage_remove_key(_path, name);
    free(_path);

    return rtval;
}

const struct fuse_operations xmp_oper = {
        .init        = xmp_init,
        .getattr     = xmp_getattr,
        .access      = xmp_access,
        .readlink    = xmp_readlink,
        .opendir     = xmp_opendir,
        .readdir     = xmp_readdir,
        .releasedir  = xmp_releasedir,
        .mknod       = xmp_mknod,
        .mkdir       = xmp_mkdir,
        .symlink     = xmp_symlink,
        .unlink      = xmp_unlink,
        .rmdir       = xmp_rmdir,
        .rename      = xmp_rename,
        .link        = xmp_link,
        .chmod       = xmp_chmod,
        .chown       = xmp_chown,
        .truncate    = xmp_truncate,
#ifdef HAVE_UTIMENSAT
        .utimens     = xmp_utimens,
#endif
        .create      = xmp_create,
        .open        = xmp_open,
        .read        = xmp_read,
        .read_buf    = xmp_read_buf,
        .write       = xmp_write,
        .write_buf   = xmp_write_buf,
        .statfs      = xmp_statfs,
        .flush       = xmp_flush,
        .release     = xmp_release,
        .fsync       = xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
        .fallocate   = xmp_fallocate,
#endif
        .setxattr    = sidecar_setxattr,
        .getxattr    = sidecar_getxattr,
        .listxattr   = sidecar_listxattr,
        .removexattr = sidecar_removexattr,
#ifdef HAVE_LIBULOCKMGR
        .lock        = xmp_lock,
#endif
        .flock       = xmp_flock,
#ifdef HAVE_COPY_FILE_RANGE
        .copy_file_range = xmp_copy_file_range,
#endif
        .lseek       = xmp_lseek,
};

