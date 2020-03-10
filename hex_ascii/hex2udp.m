function udp=hex2udp(hexstr,out_mode)
  %function udp=hex2udp(hexstr,out_mode)
  % split up 1-d hex string, convert to struct representing udp.
  % out_mode = 'dec' convert the hex digits to numbers.
  % out_mode = 'hex' for the input just split up into fields
  if length(hexstr)< 32/4
    error('bad udp length');
  end
  if ~exist('out_mode','var')
    out_mode='hex';
  end
  if ~regexp('out_mode','hex|dec','once')
    error('bad output mode converting hex to udp struct');
  end
% 4x 16-bit vars + data
%  source_port,dest_port
%  length,checksum
  udp.srcport=hexstr(1:4);
  udp.dstport=hexstr(5:8);
  udp.length=hexstr(9:12);
  udp.checksum=hexstr(13:16);
  if strcmp(out_mode,'dec')
    fields=fieldnames(udp);
    for fn=1:numel(fields)
      udp.(fields{fn})=hex2num(udp.(fields{fn}),'uint16');
    end
  end
  if numel(hexstr>=17)
    udp.payload=hexstr(17:end);
  else 
    udp.payload='';
  end
end
