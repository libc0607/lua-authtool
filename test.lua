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
auth.eap(
  toHex([[\xff\xff\xff\xff\xff\xff]]), toHex([[\x00\x23\x74\x33\x68\x89]]),
  "eth0", toHex([[\x01\x00\x01\x34]])
)
