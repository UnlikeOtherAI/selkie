// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

// Vendored fix: the ctl_info / sockaddr_ctl structs below use u_int32_t, u_char and
// u_int16_t, which are declared in <sys/types.h>. Upstream relied on this being pulled
// in transitively, but Xcode 16+/26 strict Clang modules require the direct include.
#include <sys/types.h>
#include "key.h"
#include "x25519.h"

/* From <sys/kern_control.h> */
#define CTLIOCGINFO 0xc0644e03UL
struct ctl_info {
    u_int32_t   ctl_id;
    char        ctl_name[96];
};
struct sockaddr_ctl {
    u_char      sc_len;
    u_char      sc_family;
    u_int16_t   ss_sysaddr;
    u_int32_t   sc_id;
    u_int32_t   sc_unit;
    u_int32_t   sc_reserved[5];
};
