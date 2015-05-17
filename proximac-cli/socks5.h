/*
 * socks5.h - Define SOCKS5's header
 *
 * Copyright (C) 2013, clowwindy <clowwindy42@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _SOCKS5_H
#define _SOCKS5_H

#define REP_OK 0
#define SVERSION 0x05
#define CONNECT 0x01
#define ATYP_OK 0x01
#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define IPV6 0x04
#define CMD_NOT_SUPPORTED 0x07
#define HEXZERO 0x00
#define SOCKS5_FISRT_REQ_SIZE 3
#define SOCKS5_FISRT_RESP_SIZE 2

#pragma pack(1)

// struct method_select_request {
//     char ver;
//     char nmethods;
//     char methods[255];
// };

typedef struct method_select_response {
    char ver;
    char method;
} method_select_response_t;

typedef struct socks5_req_or_resp {
    char ver;
    char cmd_or_resp;
    char rsv;
    char atyp;
    char ipv4_A;
    char ipv4_B;
    char ipv4_C;
    char ipv4_D;
    char port_lsb;
    char port_hsb;
} socks5_req_or_resp_t;

#endif //_SOCKS5_H

