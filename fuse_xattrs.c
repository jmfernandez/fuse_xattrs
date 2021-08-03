/*
  fuse_xattrs - Add xattrs support using sidecar files

  Copyright (C) 2016-2017  Felipe Barriga Richards <felipe {at} felipebarriga.cl>

  Based on passthrough.c (libfuse example)

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#define FUSE_USE_VERSION 30

/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700

/* For get_current_dir_name */
#ifndef _GNU_SOURCE
#   define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

#include <fuse.h>
#include <fuse_opt.h>
#if !defined(__CYGWIN__)
#  include <fuse_lowlevel.h>
#endif

#include "fuse_xattrs_config.h"

#include "xattrs_config.h"
#include "utils.h"
#include "passthrough.h"

# ifdef HAVE_ERROR_H
#  include <error.h>
# else
#  define error(status, errno, fmt, ...) do {                           \
    if (errno == 0)                                                     \
      fprintf (stderr, "fuse-overlayfs: " fmt "\n", ##__VA_ARGS__);     \
    else                                                                \
      {                                                                 \
        fprintf (stderr, "fuse-overlayfs: " fmt, ##__VA_ARGS__);        \
        fprintf (stderr, ": %s\n", strerror (errno));                   \
      }                                                                 \
    if (status)                                                         \
      exit (status);                                                    \
  } while(0)
# endif

struct xattrs_config xattrs_config;

/**
 * Check if the path is valid. If it's a relative path,
 * prepend the working path.
 * @param path relative or absolute path to eval.
 * @return new string with absolute path
 */
const char *sanitized_source_directory(const char *path) {
    char *absolute_path;
    if (strlen(path) == 0) {
        return NULL;
    }

    /* absolute path, we don't do anything */
    if (path[0] == '/') {
        if (is_directory(path) == -1) {
            return NULL;
        }
        absolute_path = strdup(path);
        return absolute_path;
    }

    char *pwd = get_current_dir_name();
    size_t len = strlen(pwd) + 1 + strlen(path) + 1;
    int has_trailing_backslash = (path[strlen(path)-1] == '/');
    if (!has_trailing_backslash)
        len++;

    absolute_path = (char*) malloc(sizeof(char) * len);
    memset(absolute_path, '\0', len);
    sprintf(absolute_path, "%s/%s", pwd, path);

    if(!has_trailing_backslash)
        absolute_path[len-2] = '/';

    if (is_directory(absolute_path) == -1) {
        free(absolute_path);
        return NULL;
    }

    return absolute_path;
}

enum {
    KEY_HELP,
    KEY_VERSION,
};

#define FUSE_XATTRS_OPT(t, p, v) { t, offsetof(struct xattrs_config, p), v }

static struct fuse_opt xattrs_opts[] = {
        FUSE_XATTRS_OPT("show_sidecar", show_sidecar, 1),

        FUSE_XATTRS_OPT("-V",           show_version, 1),
        FUSE_XATTRS_OPT("--version",    show_version, 1),
        FUSE_XATTRS_OPT("-h",           show_help,    1),
        FUSE_XATTRS_OPT("--help",       show_help,    1),
        FUSE_XATTRS_OPT("-d",           debug,        1),
        FUSE_XATTRS_OPT("debug",        debug,        1),
        FUSE_XATTRS_OPT("-v",           verbose,      1),
        FUSE_XATTRS_OPT("verbose",      verbose,      1),
        FUSE_XATTRS_OPT("-f",           foreground,   1),
        FUSE_XATTRS_OPT("-s",           singlethread, 1),
        FUSE_OPT_END
};

static void usage(const char * progname) {
    fprintf(stderr,
            "usage: %s source_dir mountpoint [options]\n"
                    "\n"
                    "general options:\n"
                    "    -o opt,[opt...]  mount options\n"
                    "    -h   --help      print help\n"
                    "    -V   --version   print version\n"
                    "\n"
                    "FUSE XATTRS options:\n"
                    "    -o show_sidecar  don't hide sidecar files\n"
                    "\n",
                    "FUSE Options:\n",
    progname);
}

static int xattrs_opt_proc(void *data, const char *arg, int key,
                           struct fuse_args *outargs) {
    (void) data;
    switch (key) {
        case FUSE_OPT_KEY_NONOPT:
            if (!xattrs_config.source_dir) {
                xattrs_config.source_dir = sanitized_source_directory(arg);
                xattrs_config.source_dir_size = strlen(xattrs_config.source_dir);
                return 0;
            } else if(!xattrs_config.mountpoint) {
                int fd, len;
                if (sscanf(arg, "/dev/fd/%u%n", &fd, &len) == 1 && len == strlen(arg)) {
                    /*
                     * Allow /dev/fd/N unchanged; it can be
                     * use for pre-mounting a generic fuse
                     * mountpoint to later be completely
                     * unprivileged with libfuse >= 3.3.0.
                     */
                    xattrs_config.mountpoint = strdup(arg);
                } else {
                    xattrs_config.mountpoint = realpath(arg, NULL);
                }
                if (!xattrs_config.mountpoint) {
                    fprintf(stderr, "fuse_xattrs: bad mount point `%s': %s\n",
                            arg, strerror(errno));
                    return -1;
                }
                return 0;
            }
            fprintf(stderr, "fuse_xattrs: invalid argument `%s'\n", arg);
            return -1;
            
            break;

        case KEY_HELP:
            usage(outargs->argv[0]);
            fuse_lib_help(outargs);
            exit(1);

        case KEY_VERSION:
            printf("FUSE_XATTRS version %d.%d\n", FUSE_XATTRS_VERSION_MAJOR, FUSE_XATTRS_VERSION_MINOR);
            fuse_opt_add_arg(outargs, "--version");
            fuse_main(outargs->argc, outargs->argv, &xmp_oper, NULL);
            exit(0);
        default:
            fputs("internal error\n", stderr);
            abort();
    }
    return 1;
}

static int fuse_xattrs_start(void) {
    /* To be used for complex initializations */
    return 0;
}


int main(int argc, char *argv[]) {
    int res;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse *fuse;
    struct fuse_session * se;
    
    xattrs_config.show_sidecar = 0;
    xattrs_config.show_version = 0;
    xattrs_config.show_help = 0;
    xattrs_config.singlethread = 0;
    xattrs_config.foreground = 0;
    xattrs_config.debug = 0;
    xattrs_config.verbose = 0;
    
    if (fuse_opt_parse(&args, &xattrs_config, xattrs_opts, xattrs_opt_proc) == -1) {
        exit(1);
    }
    if (xattrs_config.show_version) {
            printf("FUSE_XATTRS version %d.%d\n", FUSE_XATTRS_VERSION_MAJOR, FUSE_XATTRS_VERSION_MINOR);
            printf("FUSE library version %s\n", fuse_pkgversion());
#if !defined(__CYGWIN__)
            fuse_lowlevel_version();
#endif
            exit(0);
    }
    
    if (xattrs_config.show_help) {
            usage(args.argv[0]);
            fuse_lib_help(&args);
            exit(0);
    }
    if (!xattrs_config.source_dir) {
        fprintf(stderr, "missing source directory\n");
        fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
        exit(1);
    }
    if (!xattrs_config.mountpoint) {
        fprintf(stderr, "missing mountpoint\n");
        fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
        exit(1);
    }

    umask(0);
    fuse = fuse_new(&args, &xmp_oper, sizeof(struct fuse_operations), NULL);
    if (fuse == NULL)
        exit(1);
    se = fuse_get_session(fuse);
    res = fuse_set_signal_handlers(se);
    if (res != 0) {
        fuse_destroy(fuse);
        exit(1);
    }
    
    res = fuse_mount(fuse, xattrs_config.mountpoint);
    if (res != 0) {
        fuse_destroy(fuse);
        exit(1);
    }
    #if !defined(__CYGWIN__)
        res = fcntl(fuse_session_fd(se), F_SETFD, FD_CLOEXEC);
        if (res == -1)
            perror("WARNING: failed to set FD_CLOEXEC on fuse device");
    #endif
    
    res = fuse_xattrs_start();
    if (res == -1) {
        fuse_unmount(fuse);
        fuse_destroy(fuse);
        exit(1);
    }
    
    res = fuse_daemonize(xattrs_config.foreground);
    if (res == -1) {
        fuse_unmount(fuse);
        fuse_destroy(fuse);
        exit(1);
    }
    
    if (xattrs_config.singlethread)
        res = fuse_loop(fuse);
    else
        res = fuse_loop_mt(fuse, 0);
    
    if (res!=0)
        res = 1;
    
    fuse_remove_signal_handlers(se);
    fuse_unmount(fuse);
    fuse_destroy(fuse);
    
    fuse_opt_free_args(&args);
    
    return res;
}
