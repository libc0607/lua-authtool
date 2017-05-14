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
authtool_open(lua_State *L)
{
	int32_t on = 1;		// ???
	int32_t argc, length;
	static int32_t auth_8021x_sock = 0;
	static int32_t auth_udp_sock = 0;

	argc = lua_gettop(L);
	if (argc != 1)
		return luaL_error(L, "Argument error: \n\topen(ifname) \n");

	// ifname should be at the top of the stack now
	// so directly push it into register
	lua_setfield(L, LUA_REGISTRYINDEX, "authtool_ifname");

	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if ((setsockopt(auth_8021x_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}
	// 放入注册表
	lua_pushnumber(L, auth_8021x_sock);
	lua_setfield(L, LUA_REGISTRYINDEX, "auth_8021x_sock");

	auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (auth_udp_sock < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}
	lua_pushnumber(L, auth_udp_sock);
	lua_setfield(L, LUA_REGISTRYINDEX, "auth_udp_sock");

	lua_pushnumber(L, SUCCESS);
	return 1;
}

static int32_t
authtool_close(lua_State *L)
{
	int32_t auth_udp_sock, auth_8021x_sock;

	lua_getfield(L, LUA_REGISTRYINDEX, "auth_udp_sock");
	auth_udp_sock = lua_tointeger(L, -1);
	lua_getfield(L, LUA_REGISTRYINDEX, "auth_8021x_sock");
	auth_8021x_sock = lua_tointeger(L, -1);

	if ((0 == close(auth_udp_sock)) && (0 == close(auth_8021x_sock))) {
		lua_pushnumber(L, SUCCESS);
		return 1;
	}
	lua_pushnumber(L, ERR_SOCKET);
	return 1;
}

static int32_t
authtool_send_eap(lua_State *L)
{
	fd_set fdR;
	int32_t argc, mode;
	static int32_t lua_callback = LUA_REFNIL;
	int8_t * smac_char, dmac_char, data_char;
	size_t length;
	uint8_t data_send[1024] = {0};		// 要发送的数据包的（原始形态，包含二层的) 假设1024字节够用 23333
	uint8_t data_recv_buf[1024] = {0};
	int8_t ifname[16] = {0};

	struct ifreq ifr;
	int32_t auth_8021x_sock;
	struct sockaddr_ll auth_8021x_addr;

	struct timeval timeout = {0, 0};
	struct timeval tmp_timeout = timeout;
	static time_t time_base = 0;

	// 获取参数
	argc = lua_gettop(L);
	if (argc < 3 || argc > 4)
		return luaL_error(L, "Argument error: \n\teap(dmac, smac, data, function) \n");

	dmac_char = lua_tolstring(L, 1, &length);
	smac_char = lua_tolstring(L, 2, &length);
	memcpy(data_send, dmac_char, 6);
	memcpy(data_send + 6, smac_char, 6);
	data_send[12] = 0x88;
	data_send[13] = 0x8e;

	if (argc == 3) {
		if (1 == lua_isfunction(L, -1)) {
			lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
			mode = 2;
		}	else {
			data_char = lua_tolstring(L, -1, &length);
			memcpy(data_send + 14, data_char, length + 1); 		// skip 14 bytes eth header
			mode = 1;
		}
	} else {
		data_char = lua_tolstring(L, 3, &length);
		memcpy(data_send + 14, data_char, length + 1);
		lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
		mode = 3;
	}

	// 从lua注册表获取 socket描述符 & 网卡名 & 超时
	// todo：错误处理
	lua_getfield(L, LUA_REGISTRYINDEX, "auth_8021x_sock");
	auth_8021x_sock = lua_tointeger(L, -1);
	lua_getfield(L, LUA_REGISTRYINDEX, "authtool_ifname");
	strncpy(ifname, lua_tolstring(L, -1, &length), length + 1);
	lua_getglobal(L, AUTHTOOL_LIB_NAME);
	lua_getfield(L, -1, "eap_recv_timeout");
	timeout.tv_sec = lua_tointeger(L, -1);

	// 设置 8021x socket
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);  	// global variable <ifname>
	if(ioctl(auth_8021x_sock, SIOCGIFFLAGS, &ifr) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}
	if(ioctl(auth_8021x_sock, SIOCGIFINDEX, &ifr) < 0) {
		lua_pushnumber(L, ERR_SOCKET);
		return 1;
	}

	bzero(&auth_8021x_addr, sizeof(auth_8021x_addr));
	auth_8021x_addr.sll_ifindex = ifr.ifr_ifindex;
	auth_8021x_addr.sll_family = PF_PACKET;
	auth_8021x_addr.sll_protocol  = htons(ETH_P_PAE);
	auth_8021x_addr.sll_pkttype = PACKET_HOST;

	// 发送
	if (mode == 1 || mode == 3) {
		if (0 == _auth_8021x_sender(auth_8021x_sock, data_send, length + 14, auth_8021x_addr)) {
			lua_pushnumber(L, ERR_SOCKET);
			return 1;
		}
	}


	if (mode == 2 || mode == 3) {
		time_base = time(NULL);
		while(time(NULL) - time_base < timeout.tv_sec) {
			FD_ZERO(&fdR);
			FD_SET(auth_8021x_sock, &fdR);
			tmp_timeout = timeout;
			switch(select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
				case -1:
					lua_pushnumber(L, ERR_SOCKET);
					return 1;
				break;
				case 0:
					lua_pushnumber(L, ERR_TIMEOUT);
					return 1;
				break;
				default:
					if (FD_ISSET(auth_8021x_sock, &fdR)) {
						if(_auth_8021x_receiver(auth_8021x_sock, smac_char, data_recv_buf, auth_8021x_addr)) {
							// 调用lua的那个callback
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
	// 大概。。是结束了吧？
	lua_pushnumber(L, SUCCESS);
	return 1;
}

static int32_t
authtool_send_udp(lua_State *L)
{
	fd_set fdR;
	uint8_t * server_ip = "";
	uint8_t * client_ip = "";
	uint16_t server_port = 0;
	uint16_t client_port = 0;
	size_t length;

	int32_t argc, mode;
	static int32_t lua_callback = LUA_REFNIL;
	struct sockaddr_in server_addr, client_addr;
	int8_t * data_char = {0};
	uint8_t data_send[1024] = {0};
	uint8_t data_recv_buf[1024] = {0};
	int32_t auth_udp_sock = 0;

	struct timeval timeout = {0, 0};	// 抄来的，不知道为啥
	struct timeval tmp_timeout = timeout;
	static time_t time_base = 0;

	// 获取参数
	argc = lua_gettop(L);
	if (argc < 5 || argc > 6)
		return luaL_error(L, "Argument error: \n\tudp(dst_ip, dst_port, src_ip, src_port, data, func(RECEIVED_DATA)) \n");

	server_ip = lua_tolstring(L, 1, &length);
	server_port = lua_tointeger(L, 2);
	client_ip = lua_tolstring(L, 3, &length);
	client_port = lua_tointeger(L, 4);

	lua_getfield(L, LUA_REGISTRYINDEX, "auth_udp_sock");
	auth_udp_sock = lua_tointeger(L, -1);
	lua_getglobal(L, AUTHTOOL_LIB_NAME);
	lua_getfield(L, -1, "udp_recv_timeout");
	timeout.tv_sec = lua_tointeger(L, -1);

	if (argc == 5) {
		if (1 == lua_isfunction(L, -1)) {
			lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
			mode = 2;
		}	else {
			data_char = lua_tolstring(L, -1, &length);
			memcpy(data_send, data_char, length);
			mode = 1;
		}
	} else {
		data_char = lua_tolstring(L, 5, &length);
		memcpy(data_send, data_char, length);
		lua_callback = luaL_ref(L, LUA_REGISTRYINDEX);
		mode = 3;
	}

	bzero(&server_addr, sizeof(server_addr));
	bzero(&client_addr, sizeof(client_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip);
	server_addr.sin_port = htons(server_port);
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr(client_ip);
	client_addr.sin_port = htons(client_port);

	bind(auth_udp_sock, (struct sockaddr *)&(client_addr), sizeof(client_addr));

	if (mode == 1 || mode == 3) {
		if (!_auth_udp_sender(auth_udp_sock, data_send, length, server_addr)) {
			lua_pushnumber(L, ERR_SOCKET);
			return 1;
		}
	}


	if (mode == 2 || mode == 3) {
		time_base = time(NULL);
		while(time(NULL) - time_base < timeout.tv_sec) {
			FD_ZERO(&fdR);
			FD_SET(auth_udp_sock, &fdR);
			tmp_timeout = timeout;
			switch (select(auth_udp_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
				case -1:
					lua_pushnumber(L, ERR_SOCKET);
					return 1;
				break;
				case 0:
					lua_pushnumber(L, ERR_TIMEOUT);
					return 1;
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
	lua_pushnumber(L, SUCCESS);
	return 1;
}
