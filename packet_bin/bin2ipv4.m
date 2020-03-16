function ipv4=bin2ipv4(bin,verbosity)
% function ipv4=ipv4(bin)
% split up 1-d bin string struct representing ipv4.
  if length(bin)< 6*4
    error('bad ipv4 length');
  end
  if ~exist('out_mode','var')
    out_mode='helpful';
  end
  if ~exist('verbosity','var')
    verbosity=10;
  end
  % 0..31
  ipv4.version=bitshift(bin(1),-4);
  ipv4.IHL=bitshift(bin(1),-4);
  t=bin(2);
  ipv4.DSCP=bitshift(bin(2),2);
  ipv4.ECN=bitshift(bin(2),6);
  if (ipv4.DSCP~=0 || ipv4.ECN~=0) && verbosity>5
    warning('UNTESTED bits in header, these fields require validation. DSCP:%i ECN:%i',ipv4.DSCP,ipv4.ECN);
  end
  ipv4.total_length=typecast(bin(3:4),'uint16');
  % 32..63
  % Id can stay hex string since its an identifier of datagram
  ipv4.id=typecast(bin(5:6),'uint16');
  ipv4.flags=bitshift(bin(7),-5);
  ipv4.fragment_offset=typecast(bin(7:8),'uint16');
  % shift 3 to bump off the flag bits, then take us back.
  ipv4.fragment_offset=bitshift(ipv4.fragment_offset,3);
  ipv4.fragment_offset=bitshift(ipv4.fragment_offset,-3);
  if ipv4.fragment_offset>0
    error('framenting unhandled ');
  end
  % 64..95
  ipv4.TTL=bin(9);
  ipv4.protocol=bin(10);
  % see wikipedia for protocol numbers 
  % https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
  % udp is 17
  ipv4.cksum=typecast(bin(11:12),'uint16');
  % 96:127
  %ipv4.src=ip_conv(bin(13:16),'dec2ip');
  ipv4.src=bin(13:16);
  % 128:159
  %ipv4.dst=ip_conv(bin(17:20),'dec2ip');
  ipv4.dst=bin(17:20);
  if ipv4.IHL>5 
    error('Options unimplemented');
    ipv4.options='';
  end
  ipv4.payload=bin(ipv4.IHL*4+1:end);
end
