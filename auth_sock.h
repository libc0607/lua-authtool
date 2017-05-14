#ifndef __AUTH_SOCK_H__
#define __AUTH_SOCK_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include <lua.h>
#include <lauxlib.h>

#define SUCCESS      1
#define ERR_SOCKET   -1
#define ERR_INPUT    -2
#define ERR_TIMEOUT  -3
#define ERR_FUNC1      -4

#define AUTHTOOL_LIB_NAME "authtool"
#define VERSION "0.0.1"


static int32_t authtool_open(lua_State *L);
static int32_t authtool_close(lua_State *L);
static int32_t authtool_send_eap(lua_State *L);
static int32_t authtool_send_udp(lua_State *L);


#endif
