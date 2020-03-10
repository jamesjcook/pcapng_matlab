function ip=ip_conv(ip,type)
  % out = ip_conv(in, conversion_op);
  % flops between ip,dec,hex,bin
  % eg intype2outtype, ip2dec, ip2bin etc.
  % ex, ip = '0.0.0.0'; % a string with period's separating numbers
  % dec=[ 0,0,0,0 ]; % 4x decimal numbers in a vector
  % hex=['00'; '00'; '00'; '00']; % 4 2 digit hex strings, also works with row or column vectors, but less reliable. 
  % bin = [ 0 ]; % 32-bit uint 
  if ~exist('type','var')
    type='ip2dec';
  end
  C=strsplit(type,'2');
  cur=C{1};
  dest=C{2};
  clear C;
  % internally all ip's get converted to 4x8bit uint before getting converted back.
  bin=zeros(1,4,'uint8');
  if strcmp(cur,'ip')
    octet_str=strsplit(ip,'.');
    bin=zeros(1,4,'uint8');
    for i_o=1:numel(octet_str)
      bin(i_o)=uint8(str2num(octet_str{i_o}));
    end
  elseif strcmp(cur,'hex')
    if numel(ip)==4&&iscell(ip)
      ip=strjoin(ip,'');
    end
    ip=reshape(ip,[2,4]);
    ip=permute(ip,[2,1]);
    bin=hex2num(ip,'uint8');
  elseif strcmp(cur,'dec')
    ip=cast(ip,'uint8');
    bin=typecast(ip,'uint8');
  elseif strcmp(cur,'bin')
    % no-op error('unimplemented');
  end
  clear ip;

  if strcmp(dest,'ip')
    ip=sprintf('%i.%i.%i.%i', typecast(bin,'uint8') );
  elseif strcmp(dest,'hex')
    ip=sprintf('%02x',bin);
    ip=reshape(ip,[2,4]);
    ip=permute(ip,[2,1]);
    %ip=sprintf('%s ',ip);
  elseif strcmp(dest,'dec')
    ip=typecast(bin,'uint8');
  elseif strcmp(dest,'bin')
    ip=bin;
    % return.
  end
return;