/*
 * Copyright (c) 2017 libc0607 <libc0607@gmail.com>
 *
 * 下面都是复制的我也不知道啥意思
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "auth_sock.h"


LUALIB_API int luaopen_authtool(lua_State *L) {

    int i;
    const luaL_reg functions[] = {
        { "open", authtool_open },
        { "close", authtool_close },
        { "eap", authtool_send_eap },
        { "udp", authtool_send_udp },
        { NULL, NULL }
    };
    const struct {
        const char *name;
        int value;
    } const_number[] = {
        { "eap_recv_timeout", 3 },    // default
        { "udp_recv_timeout", 3 },
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
