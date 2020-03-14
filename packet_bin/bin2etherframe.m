function frame=bin2etherframe(bin,endian)
  % function phy=hex2phy(hexstr)
  % split up 1-d hex string into ... ether frame parts. 
  
  frame.dst=bin(1:6); % 6
  frame.src=bin(7:12); % 12
  frame.type=bin(13:14); % 24
  frame.payload=bin(15:end);
  
end
