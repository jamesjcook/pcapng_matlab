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
  if strcmp(out_mode,'dec')
    udp.srcport=typecast(bin(1:2),'uint16');
    udp.dstport=typecast(bin(3:4),'uint16');
    udp.length=typecast(bin(5:6),'uint16');
    udp.checksum=typecast(bin(7:8),'uint16');
  elseif strcmp(out_mode,'hex')
    udp.srcport=num2hex(typecast(bin(1:2),'uint16'));
    udp.dstport=num2hex(typecast(bin(3:4),'uint16'));
    udp.length=num2hex(typecast(bin(5:6),'uint16'));
    udp.checksum=num2hex(typecast(bin(7:8),'uint16'));
  else
    error(' unkown out for bin2udp');
    %{
    fields=fieldnames(udp);
    for fn=1:numel(fields)
      udp.(fields{fn})=typecast(udp.(fields{fn}),'uint16');
    end
    %}
  end
  if numel(bin>=9)
    udp.payload=bin(9:end);
  else 
    udp.payload='';
  end
end
