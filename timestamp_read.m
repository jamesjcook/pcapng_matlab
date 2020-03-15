function timestamp=timestamp_read(in)
  timestamp_H=fread(in,1,'uint32=>uint32');
  timestamp_L=fread(in,1,'uint32=>uint32');
  timestamp=[timestamp_L,timestamp_H];
  timestamp=typecast(bl.timestamp,'uint64');
  