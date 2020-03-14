function udp=bin2udp(bin,out_mode)
  %function udp=udp(bin,out_mode)
  % split up 1-d hex string, convert to struct representing udp.
  % out_mode = 'dec' convert the hex digits to numbers.
  % out_mode = 'hex' hex strings
  if length(bin)< 8
    error('bad udp length');
  end
  if ~exist('out_mode','var')
    out_mode='dec';
  end
  %{
  if ~regexp('out_mode','hex|dec','once')
    error('bad output mode converting hex to udp struct');
  end
  %}
% 4x 16-bit vars + data
%  source_port,dest_port
%  length,checksum
  udp.srcport=bin(1:2);
  udp.dstport=bin(3:4);
  udp.length=bin(5:6);
  udp.checksum=bin(7:8);
  if strcmp(out_mode,'dec')
    fields=fieldnames(udp);
    for fn=1:numel(fields)
      udp.(fields{fn})=typecast(udp.(fields{fn}),'uint16');
    end
  end
  if numel(bin>=9)
    udp.payload=bin(9:end);
  else 
    udp.payload='';
  end
end
