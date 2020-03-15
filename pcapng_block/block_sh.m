function bl=block_sh(in,  magic_numbers,  blk_len,  block_type)
% Section Header Block
%{
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                   Block Type = 0x0A0D0D0A                     |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                      Byte-Order Magic                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |          Major Version        |         Minor Version         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                                                               |
   |                          Section Length                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
%}
  % section header.... get endian for section
  bl.byte_magic=fread(in,1,'uint32=>uint32');
  if bl.byte_magic==magic_numbers.endian
    % native byte ording
  elseif swapbytes(bl.byte_magic)==magic_numbers.endian
    % swap our bytes :p
    % but wait... we don't know which we are ?
    error('Endian handling incomplete');
    % I think that means we cant set which endian we are, just that we need to swap.
  else 
    % byte error
    error('byte magic not comprehensible :( Potential data corruption');
  end
  bl.vers_major=fread(in,1,'uint16=>uint16');
  bl.vers_minor=fread(in,1,'uint16=>uint16');
  bl.section_length=fread(in,1,'int64=>int64');
  if bl.section_length==-1
    % unspecified length
  end
  end
  opt_len=blk_len-24-4;
  if opt_len>0
    bl.options=pcapng_option_read(in,opt_len,block_type);
  end
  
end
