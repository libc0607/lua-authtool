# lua-authtool
一个Linux下 raw socket 的简单的 Lua Binding  

本来是试图简化校园网认证程序在OpenWrt/LEDE上的开发难度的工具，然后不小心把轮子造成了阻塞的，至于异步版大概。。有生之年吧  

# 编译
需要Lua环境 仅在Ubuntu 16.04 x64 + Lua 5.1.5下试过  

编译的话直接make即可  

# 使用
require后直接用就行，需要sudo运行  

具体参考[test.lua](https://github.com/libc0607/lua-authtool/blob/master/test.lua)  
