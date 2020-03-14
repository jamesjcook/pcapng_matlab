function phy=hex2phy(hexstr)
  % function phy=hex2phy(hexstr)
  % split up 1-d hex string into ... ether frame parts. 
  phy.dst=hexstr(1:12);
  phy.src=hexstr(13:24);
  phy.type=hexstr(25:28);
  phy.payload=hexstr(29:end);
end
