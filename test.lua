local auth = require("authtool")

function toHex (d)
  local s
  s,_=d:gsub("\\x(%x%x)",function(x) return string.char(tonumber(x,16)) end)
  return s
end

function toDec (d)
  local i
  local s=""
  for i=1, d:len() do
    s=s..string.format("\\x%2X",d:byte(i))
  end
  return s
end

-- 包的内容我随便写的 不用在意

-- eap, send a start packet, then wait 3 seconds for receive
print("eap send & receive")
print(auth.eap(
  toHex([[\xff\xff\xff\xff\xff\xff]]),
  toHex([[\x00\x23\x74\x33\x68\x89]]),
  "eth0",
  toHex([[\x01\x01\x00\x00]]),
  3
))


-- eap, wait 3 seconds for receive
print("eap receive only")
print(auth.eap(
  toHex([[\xff\xff\xff\xff\xff\xff]]),
  toHex([[\x00\x23\x74\x33\x68\x89]]),
  "eth0",
  3
))


-- udp, send a Drcom start packet, then receive
print("udp send & receive")
print(auth.udp(
  "192.168.159.1", 61440,
  "192.168.159.129", 61440,
  toHex([[\x07\x00\x08\x00\x01\x00\x00\x00]]),
  5
))


-- udp, receive only
print("udp receive")
print(auth.udp(
  "192.168.159.1", 61440,
  "192.168.159.129", 61440,
  5
))
