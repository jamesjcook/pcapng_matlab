function ipv4=hex2ipv4(hexstr,out_mode,verbosity)
% function ipv4=hex2ipv4(hexstr,out_mode)
% split up 1-d hex string struct representing ipv4.
% outmode is 'hex' for simply splitting up the header, or helpful...
% helpful tries to fit data to binary type.
  if length(hexstr)< 5*32/4
    error('bad ipv4 length');
  end
  if ~exist('out_mode','var')
    out_mode='helpful';
  end
  if ~exist('verbosity','var')
    verbosity=10;
  end
  % 0..31
  ipv4.version=bitshift(hex2num(hexstr(1),'uint8'),-4);
  ipv4.IHL=bitshift(hex2num(hexstr(2),'uint8'),-4);
  t=hexstr(3:4);
  ipv4.DSCP=bitshift(hex2num(t,'uint8'),2);
  ipv4.ECN=bitshift(hex2num(t,'uint8'),6);
  if (ipv4.DSCP~=0 || ipv4.ECN~=0) && verbosity>5
    warning('UNTESTED bits in header, these fields require validation. DSCP:%i ECN:%i',ipv4.DSCP,ipv4.ECN);
  end
  ipv4.total_length=hex2num(hexstr(5:8),'uint16');
  % 32..63
  % Id can stay hex string since its an identifier of datagram
  ipv4.id=hexstr(9:12);
  t=hexstr(13:16);
  ipv4.flags=uint8(bitshift(hex2num(t),-13));
  ipv4.fragment_offset=hex2num(t,'uint16');
  % shift 3 to bump off the flag bits, then take us back.
  ipv4.fragment_offset=bitshift(ipv4.fragment_offset,3);
  ipv4.fragment_offset=bitshift(ipv4.fragment_offset,-3);
  if ipv4.fragment_offset>0
    error('framenting unhandled ');
  end
  % 64..95
  ipv4.TTL=hex2num(hexstr(17:18),'uint8');
  ipv4.protocol=hex2num(hexstr(19:20),'uint8');
  % see wikipedia for protocol numbers 
  % https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
  % udp is 17
  ipv4.cksum=hexstr(21:24);
  % 96:127
  ipv4.src=ip_conv(hexstr(25:32),'hex2ip');
  % 128:159
  ipv4.dst=ip_conv(hexstr(33:33+8-1),'hex2ip');
  if ipv4.IHL>5 
    error('Options unimplemented');
    ipv4.options='';
  end
  ipv4.payload=hexstr(ipv4.IHL*8+1:end);
end
