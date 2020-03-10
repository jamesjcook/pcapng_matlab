
function ep=block_ep(input,blk_len,block_type,idb)
% Enhanced Packet Block (EPB)
%{
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000006                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                         Interface ID                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 |                    Captured Packet Length                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 |                    Original Packet Length                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28 /                                                               /
   /                          Packet Data                          /
   /              variable length, padded to 32 bits               /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
%}
  if exist('idb')
    % This is here to handle the SnapLen option from interface
    error('inteface description not handled for simple sp yet.');
  end
  ep.interface=fread(input,1,'uint32=>uint32');
  timestamp_H=fread(input,1,'uint32=>uint32');
  timestamp_L=fread(input,1,'uint32=>uint32');
  ep.timestamp=[timestamp_L,timestamp_H];
  ep.timestamp=typecast(ep.timestamp,'uint64');
  ep.length=fread(input,1,'uint32=>uint32');
  ep.orig_length=fread(input,1,'uint32=>uint32');
  ep.data=fread(input,ep.length,'uint8=>uint8');
  trailing=char_alignment(ep.length);
  opt_len=blk_len-28-ep.length-trailing-4;
  if mod(opt_len,4)
    error('failure to get opt len in EPB, bad math whooo whooo!');
  end
  if opt_len>0
    %ep.options=fread(input,opt_len,'uint8=>uint8');
    ep.options=pcapng_option_read(input,opt_len,block_type);
  end
end