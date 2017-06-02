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
--
auth.eap(
  toHex([[\xff\xff\xff\xff\xff\xff]]), toHex([[\x00\x23\x74\x33\x68\x89]]),
  "eth0", toHex([[\x01\x00\x01\x34]])
)

auth.udp(
  "192.168.159.1",
  61440,
  "192.168.159.129",
  61440,
  toHex([[\x23\x33\x33\x33\x33]])

)
