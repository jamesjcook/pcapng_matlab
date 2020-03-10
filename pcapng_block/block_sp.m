
function sp=block_sp(input,blk_len,idb)
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
  if exist('idb')
    % This is here to handle the SnapLen option from interface
    error('inteface description not handled for simple packet yet.');
  end
  packet=struct;
  packet.length=fread(input,1,'uint32=>uint32');
  trailing=char_alignment(packet.length);
  packet.data=fread(input,packet.length,'uint8=>uint8');
  if trailing
    ftell
    fseek(input,trailing);
    ftell
    fprintf('Is this the problem');
  end
end
