function timestamp=timestamp_read(in)
% timestamp_H=fread(in,1,'uint32=>uint32');
% timestamp_L=fread(in,1,'uint32=>uint32');
% timestamp=[timestamp_L,timestamp_H];
  timesetamp=zeros(2,'uint32');
  timestamp(2)=fread(in,1,'uint32=>uint32');
  timestamp(1)=fread(in,1,'uint32=>uint32');
  timestamp=typecast(timestamp,'uint64');
  