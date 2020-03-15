
function id=block_id(in,  magic_numbers,  blk_len,  block_type)
% Interface Description Block
%{
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000001                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |           LinkType            |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                            SnapLen                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
%}
  id.LinkType=fread(in,1,'uint16=>uint16');
  id.Reserved=fread(in,1,'uint16=>uint16');
  id.SnapLen=fread(in,1,'uint32=>uint32');
  opt_len=blk_len-16-4;
  if mod(opt_len,4)
    error('failure to get opt len in IDB, bad math whooo whooo!');
  end
  if opt_len>0
    %id.options=fread(in,opt_len,'uint8=>uint8');
    id.options=pcapng_option_read(in,opt_len,block_type);
  end
  
end