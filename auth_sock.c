#include "auth_sock.h"

int32_t
_auth_udp_sender(int32_t sock, uint8_t *send_data, int32_t send_data_len, struct sockaddr_in serv_addr)
{
	if (sendto(sock, send_data, send_data_len, 0, &serv_addr,
          sizeof(serv_addr)) != send_data_len)
		return 0;

	return 1;
}

int32_t
_auth_udp_receiver(int32_t sock, int8_t *recv_data, struct sockaddr_in serv_addr)
{
	struct sockaddr_in clntaddr;
	int32_t recv_len, addrlen = sizeof(struct sockaddr_in);
	recv_len = recvfrom(sock, recv_data, ETH_FRAME_LEN, 0,
                    (struct sockaddr*) &clntaddr, &addrlen);
	return (recv_len > 0
	     && memcmp(&clntaddr.sin_addr, &serv_addr.sin_addr, 4) == 0
	     && recv_data[0] == 0x07)? recv_len: 0;
}

int32_t
_auth_8021x_sender(int32_t sock, uint8_t *send_data, int32_t send_data_len, struct sockaddr_ll eap_addr)
{
	if (sendto(sock, send_data, send_data_len, 0,
      (struct sockaddr *)&eap_addr, sizeof(eap_addr)) != send_data_len)
		return 0;

	return 1;
}

int32_t
_auth_8021x_receiver(int32_t sock, uint8_t *dst_mac_filter, int8_t *recv_data, struct sockaddr_ll eap_addr)
{
	struct ethhdr *recv_hdr;
	struct ethhdr *local_ethhdr;
	int32_t recv_len = recv(sock, recv_data, ETH_FRAME_LEN, 0);
	recv_hdr = (struct ethhdr *)recv_data;

	return (recv_len > 0
	     && (0 == memcmp(recv_hdr->h_dest, dst_mac_filter, ETH_ALEN))
	     && (htons(ETH_P_PAE) ==  recv_hdr->h_proto))? recv_len: 0;
}

void
dump_memory(void* p, int length, char * tag)
{
	int i, j;
	unsigned char *addr = (unsigned char *)p;

	printf("\n");
	printf("===== Memory dump at %s, length=%d =====", tag, length);
	printf("\n");

	for(i = 0; i < 16; i++)
		printf("%2x ", i);
	printf("\n");
	for(i = 0; i < 16; i++)
		printf("---");
	printf("\n");
	// 一行16个
	for(i = 0; i < (length/16) + 1; i++) {
		for(j = 0; j < 16; j++) {
			if (i * 16 + j >= length)
				break;
			printf("%2x ", *(addr + i * 16 + j));
		}
		printf("\n");
	}
	for(i = 0; i < 16; i++)
		printf("---");
	printf("\n\n");
}


static int32_t
authtool_send_eap(lua_State *L)
{
	fd_set fdR;
	int32_t argc;
	//int32_t lua_callback = LUA_REFNIL;
	int8_t * smac_char;
	int8_t * dmac_char;
	int8_t * data_char;
	int8_t * ifname_char;	// pointer got from stack
	size_t length, send_data_length, recv_data_length = 0;
	uint8_t data_send[1024] = {0};
	uint8_t data_recv_buf[1024] = {0};
	int8_t ifname[16] = {0};

	struct ifreq ifr;
	int32_t auth_8021x_sock;
	struct sockaddr_ll auth_8021x_addr;
	int32_t on = 1;		// ???

	struct timeval timeout = {0, 0};
	struct timeval tmp_timeout = timeout;
	time_t time_base = 0;

	// 获取参数
	argc = lua_gettop(L);
	if (argc < 4 || argc > 5)
		return luaL_error(L, "Argument error: \n\teap(server_mac, client_mac, ifname, data, timeout) \n");

	dmac_char = lua_tolstring(L, 1, &length);
	memcpy(data_send, dmac_char, 6);
	smac_char = lua_tolstring(L, 2, &length);
	memcpy(data_send + 6, smac_char, 6);
	ifname_char = lua_tolstring(L, 3, &length);
	memcpy(ifname, ifname_char, 4);
	data_send[12] = 0x88;
	data_send[13] = 0x8e;

	switch (argc) {
	case 4:			//.eap(dmac, smac, ifname, timeout)
		timeout.tv_sec = lua_tointeger(L, -1);
	break;
	case 5:			//.eap(dmac, smac, ifname, data, timeout)
		data_char = lua_tolstring(L, -2, &send_data_length);
		memcpy(data_send + 14, data_char, send_data_length);
		timeout.tv_sec = lua_tointeger(L, -1);
	break;
	}

	// debug message
	#if DEBUG
	if (argc == 5)
		dump_memory(data_send, send_data_length + 14, "eap_full_packet");
	#endif

	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));

	if ((setsockopt(auth_8021x_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		close(auth_8021x_sock);
		return 1;
	}

	// 设置 8021x socket
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(auth_8021x_sock, SIOCGIFFLAGS, &ifr) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		close(auth_8021x_sock);
		return 1;
	}
	if(ioctl(auth_8021x_sock, SIOCGIFINDEX, &ifr) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		close(auth_8021x_sock);
		return 1;
	}

	bzero(&auth_8021x_addr, sizeof(auth_8021x_addr));
	auth_8021x_addr.sll_ifindex = ifr.ifr_ifindex;
	auth_8021x_addr.sll_family = PF_PACKET;
	auth_8021x_addr.sll_protocol  = htons(ETH_P_PAE);
	auth_8021x_addr.sll_pkttype = PACKET_HOST;

	// 发送
	if (argc == 5) {
		if (0 == _auth_8021x_sender(auth_8021x_sock, data_send, send_data_length + 14, auth_8021x_addr)) {
			lua_pushnumber(L, ERR_SOCKET);
			close(auth_8021x_sock);
			return 1;
		}
	}

	if (argc == 4 || argc == 5) {

		time_base = time(NULL);
		while(time(NULL) - time_base < timeout.tv_sec) {
			FD_ZERO(&fdR);
			FD_SET(auth_8021x_sock, &fdR);
			tmp_timeout = timeout;
			switch(select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
			case -1:
				lua_pushnumber(L, ERR_SOCKET);
				close(auth_8021x_sock);
				return 1;
			break;
			case 0:
				// Just wait
			break;
			default:
				if (FD_ISSET(auth_8021x_sock, &fdR)) {
					recv_data_length = _auth_8021x_receiver(auth_8021x_sock, smac_char, data_recv_buf, auth_8021x_addr);
					if(recv_data_length > 0)
						time_base = 0;	// 退出循环
				}
			break;
			}
		} 	// while
	}
	if (0 == close(auth_8021x_sock)) {
		lua_pushnumber(L, SUCCESS);
		if(recv_data_length > 0) {
			lua_pushnumber(L, recv_data_length);
			lua_pushstring(L, (char*)data_recv_buf);
			return 3;
		} else {
			lua_pushnil(L);
			return 2;
		}
	} else {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}

}

static int32_t
authtool_send_udp(lua_State *L)
{
	fd_set fdR;
	int8_t * server_ip_char;
	int8_t * client_ip_char;
	int8_t * data_char;
	int8_t server_ip[16] = {0};
	int8_t client_ip[16] = {0};
	uint16_t server_port = 0, client_port = 0;
	size_t length, send_data_length, recv_data_length = 0;

	int32_t argc;
	struct sockaddr_in server_addr, client_addr;
	uint8_t data_send[1024] = {0};
	uint8_t data_recv_buf[1024] = {0};
	int32_t auth_udp_sock = 0;

	struct timeval timeout = {0, 0};
	struct timeval tmp_timeout = timeout;
	time_t time_base = 0;
	int32_t on = 1;		// ???

	// 获取参数
	argc = lua_gettop(L);
	if (argc < 5 || argc > 7)
		return luaL_error(L, "Argument error: \n\tudp(server_ip, server_port, client_ip, client_port, [data,] timeout) \n");

	server_ip_char = lua_tolstring(L, 1, &length);
	memcpy(server_ip, server_ip_char, length);		// 复制一份以免出什么奇怪的bug
	server_port = lua_tointeger(L, 2);
	client_ip_char = lua_tolstring(L, 3, &length);		// '\0' attached automatically
	memcpy(client_ip, client_ip_char, length);
	client_port = lua_tointeger(L, 4);

	switch (argc) {
	case 5:
		timeout.tv_sec = lua_tointeger(L, -1);
	break;
	case 6:
		data_char = lua_tolstring(L, -2, &send_data_length);
		memcpy(data_send, data_char, send_data_length);
		timeout.tv_sec = lua_tointeger(L, -1);
	break;
	}

	bzero(&server_addr, sizeof(server_addr));
	bzero(&client_addr, sizeof(client_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip);
	server_addr.sin_port = htons(server_port);
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr(client_ip);
	client_addr.sin_port = htons(client_port);

	auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (auth_udp_sock < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}

	bind(auth_udp_sock, (struct sockaddr *)&(client_addr), sizeof(client_addr));

	if (argc == 6) {
		#if DEBUG
		dump_memory(data_send, send_data_length , "udp_packet");		// debug, no udp header 42bytes
		#endif
		if (0 == _auth_udp_sender(auth_udp_sock, data_send, send_data_length, server_addr)) {
			lua_pushnumber(L, ERR_SOCKET);
			close(auth_udp_sock);
			return 1;
		}
	}

	if (argc == 6 || argc == 5) {
		time_base = time(NULL);
		while(time(NULL) - time_base < timeout.tv_sec) {
			FD_ZERO(&fdR);
			FD_SET(auth_udp_sock, &fdR);
			tmp_timeout = timeout;
			switch (select(auth_udp_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
			case -1:
				lua_pushnumber(L, ERR_SOCKET);
				close(auth_udp_sock);
				return 1;
			break;
			case 0:
				// Just wait
			break;
			default:
				if (FD_ISSET(auth_udp_sock, &fdR)) {
					recv_data_length = _auth_udp_receiver(auth_udp_sock, data_recv_buf, server_addr);
					if(recv_data_length > 0) {
						time_base = 0;	// 退出循环
					}
				}
			break;
			} 	//switch
		}	//while
	} // if argc == 5or6
	if (0 == close(auth_udp_sock)) {
		lua_pushnumber(L, SUCCESS);
		if (recv_data_length > 0) {
			lua_pushnumber(L, recv_data_length);
			lua_pushstring(L, (char*)data_recv_buf);
			return 3;
		} else {
			lua_pushnil(L);
			return 2;
		}
	} else {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}

}




LUALIB_API int luaopen_authtool(lua_State *L) {

    int i;
    const luaL_reg functions[] = {
        { "eap", authtool_send_eap },
        { "udp", authtool_send_udp },
        { NULL, NULL }
    };
    const struct {
        const char *name;
        int value;
    } const_number[] = {
        // return codes
        { "SUCCESS", SUCCESS },       // defined in auth_sock.h
        { "ERR_SOCKET", ERR_SOCKET },
        { "ERR_INPUT", ERR_INPUT },
        { "ERR_TIMEOUT", ERR_TIMEOUT },
        { "ERR_FUNC1", ERR_FUNC1 },
    };
    const struct {
        const char *name;
        const char *value;
    } const_string[] = {
        { "VERSION", VERSION },
    };

    if (luaL_newmetatable(L, AUTHTOOL_LIB_NAME)) {  // -1:metatable,

        lua_pushstring(L, "__index");   // -2:metatable, -1:"__index"
        lua_pushvalue(L, -2);           // -3:metatable, -2:"__index", -1:metatable
        lua_settable(L, -3);            // setmetatable(THIS_LIB, metatable) ???

        luaL_openlib(L, AUTHTOOL_LIB_NAME, functions, 0);   // stack: -1:THIS_LIB

        for (i = 0; i < sizeof(const_number) / sizeof(const_number[0]); i++) {
            lua_pushnumber(L, const_number[i].value);   // stack: -2:THIS_LIB -1:value
            lua_setfield(L, -2, const_number[i].name);  // THIS_LIB.name = value
        }
        for (i = 0; i < sizeof(const_string) / sizeof(const_string[0]); i++) {
            lua_pushstring(L, const_string[i].value);
            lua_setfield(L, -2, const_string[i].name);
        }
    }

    return 0;
}
