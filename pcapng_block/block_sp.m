function sp=block_sp(in,  blk_len,  block_type,  idb)
% Simple Packet Block (SPB) 
%{
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000003                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                    Original Packet Length                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 /                                                               /
   /                          Packet Data                          /
   /              variable length, padded to 32 bits               /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
%}
  if exist('idb','var')
    % This is here to handle the SnapLen option from interface
    error('inteface description not handled for simple bl yet.');
  end
  bl=struct;
  % this is the original packet length, the block length was already eaten by the main function.
  bl.orig_length=fread(in,1,'uint32=>uint32');
  bl.data=fread(in,bl.orig_length,'uint8=>uint8');
  trailing=char_alignment(bl.orig_length);
  scrap=fread(in,trailing,'uint8');
  opt_len=blk_len-12-bl.orig_length-trailing-4;
  if mod(opt_len,4)
    error('failure to get opt len in EPB, bad math whooo whooo!');
  end
  if opt_len>0
    bl.options=pcapng_option_read(in,opt_len,block_type);
  elseif opt_len<0
    error('Problem with packet length, need to implement maxlen from interface description');
  end
end
