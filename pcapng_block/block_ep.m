function bl=block_ep(in,  blk_len,  block_type,  idb)
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
  bl.interface=fread(in,1,'uint32=>uint32');
  bl.timestamp=timestamp_read(in);
  bl.length=fread(in,1,'uint32=>uint32');
  bl.orig_length=fread(in,1,'uint32=>uint32');
  bl.data=fread(in,bl.length,'uint8=>uint8');
  trailing=char_alignment(bl.length);
  scrap=fread(in,trailing,'uint8');
  opt_len=blk_len-28-bl.length-trailing-4;
  if mod(opt_len,4)
    error('failure to get opt len in EPB, bad math whooo whooo!');
  end
  if opt_len>0
    %bl.options=fread(in,opt_len,'uint8=>uint8');
    bl.options=pcapng_option_read(in,opt_len,block_type);
  elseif opt_len<0
    error('Problem with packet length, need to implement maxlen from interface description');
  end
end