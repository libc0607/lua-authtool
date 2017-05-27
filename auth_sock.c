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
	     && recv_data[0] == 0x07)? 1: 0;
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
	     && (htons(ETH_P_PAE) ==  recv_hdr->h_proto))? 1: 0;
}


static int32_t
authtool_send_eap(lua_State *L)
{
	fd_set fdR;
	int32_t argc;
	int32_t lua_callback = LUA_REFNIL;
	int8_t * smac_char, dmac_char, data_char;
	size_t length;
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
	if (argc < 4 || argc > 6)
		return luaL_error(L, "Argument error: \n\teap(server_mac, client_mac, ifname, data, timeout, function) \n");

	dmac_char = lua_tolstring(L, 1, &length);
	smac_char = lua_tolstring(L, 2, &length);
	memcpy(data_send, dmac_char, 6);
	memcpy(data_send + 6, smac_char, 6);
	data_send[12] = 0x88;
	data_send[13] = 0x8e;
	memcpy(ifname, lua_tolstring(L, 3, &length), length + 1);	// '\0'

	switch (argc) {
	case 4:			//.eap(dmac, smac, ifname, data)
		data_char = lua_tolstring(L, -1, &length);
		memcpy(data_send + 14, data_char, length);
	break;
	case 5:			//.eap(dmac, smac, ifname, timeout, func(RECEIVED_DATA))
		timeout.tv_sec = lua_tointeger(L, -2);
		lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
	break;
	case 6:			//.eap(dmac, smac, ifname, data, timeout, func(RECEIVED_DATA))
		data_char = lua_tolstring(L, -3, &length);
		memcpy(data_send + 14, data_char, length);
		timeout.tv_sec = lua_tointeger(L, -2);
		lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
	break;
	}

	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if ((setsockopt(auth_8021x_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		close(auth_8021x_sock);
		return 1;
	}
	// 设置 8021x socket
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);  	// global variable <ifname>
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
	if (argc == 4 || argc == 6) {
		if (0 == _auth_8021x_sender(auth_8021x_sock, data_send, length + 14, auth_8021x_addr)) {
			lua_pushnumber(L, ERR_SOCKET);
			close(auth_8021x_sock);
			return 1;
		}
	}

	if (argc == 5 || argc == 6) {
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
					if(_auth_8021x_receiver(auth_8021x_sock, smac_char, data_recv_buf, auth_8021x_addr)) {
						lua_rawgeti(L, LUA_REGISTRYINDEX, lua_callback);
						lua_pushstring(L, (char*)data_recv_buf);
						lua_pcall(L, 1, 0, 0);		// 1 arg, 0 return
						time_base = 0;	// 退出循环
					}
				}
			break;
			}
		} 	// while
	}
	if (0 == close(auth_8021x_sock)) {
		lua_pushnumber(L, SUCCESS);
		return 1;
	} else {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}

}

static int32_t
authtool_send_udp(lua_State *L)
{
	fd_set fdR;
	uint8_t * server_ip = "127.0.0.1";
	uint8_t * client_ip = "127.0.0.1";
	uint16_t server_port = 61440;
	uint16_t client_port = 61440;
	size_t length;

	int32_t argc;
	int32_t lua_callback = LUA_REFNIL;
	struct sockaddr_in server_addr, client_addr;
	int8_t * data_char = {0};
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
		return luaL_error(L, "Argument error: \n\tudp(server_ip, server_port, client_ip, client_port, data, timeout, func(RECEIVED_DATA)) \n");

	server_ip = lua_tolstring(L, 1, &length);
	server_port = lua_tointeger(L, 2);
	client_ip = lua_tolstring(L, 3, &length);		// '\0' attached automatically
	client_port = lua_tointeger(L, 4);

	switch (argc) {
	case 5:
		data_char = lua_tolstring(L, -1, &length);
		memcpy(data_send, data_char, length);
	break;
	case 6:
		lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
		timeout.tv_sec = lua_tointeger(L, -2);
	break;
	case 7:
		data_char = lua_tolstring(L, -3, &length);
		memcpy(data_send, data_char, length);
		lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
		timeout.tv_sec = lua_tointeger(L, -2);
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

	if (argc == 5 || argc == 7) {
		if (0 == _auth_udp_sender(auth_udp_sock, data_send, length, server_addr)) {
			lua_pushnumber(L, ERR_SOCKET);
			close(auth_udp_sock);
			return 1;
		}
	}

	if (argc == 6 || argc == 7) {
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
					if(_auth_udp_receiver(auth_udp_sock, data_recv_buf, server_addr)) {
						lua_rawgeti(L, LUA_REGISTRYINDEX, lua_callback);
						lua_pushstring(L, (char*)data_recv_buf);
						lua_pcall(L, 1, 0, 0);		// 1 arg, 0 return
						time_base = 0;	// 退出循环
					}
				}
			break;
			} 	//switch
		}	//while
	} // if argc == 6
	if (0 == close(auth_udp_sock)) {
		lua_pushnumber(L, SUCCESS);
		return 1;
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
