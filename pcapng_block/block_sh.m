

function sh=block_sh(input,  magic_numbers,  blk_len,  block_type)
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
  sh.byte_magic=fread(input,1,'uint32=>uint32');
  if sh.byte_magic==magic_numbers.endian
    % native byte ording
  elseif swapbytes(sh.byte_magic)==magic_numbers.endian
    % swap our bytes :p
    % but wait... we don't know which we are ?
  else 
    % byte error
    error('byte magic not comprehensible :( Potential data corruption');
  end
  sh.vers_major=fread(input,1,'uint16=>uint16');
  sh.vers_minor=fread(input,1,'uint16=>uint16');
  sh.section_length=fread(input,1,'int64=>int64');
  if sh.section_length==-1
    % unspecified length
  end
  % -24 for all we've read so far, and -4 for the trailing block len
  opt_len=blk_len-24-4;
  if opt_len>0
    % sh.options=fread(input,opt_len,'uint8=>uint8');
    sh.options=pcapng_option_read(input,opt_len,block_type);
  end
  
end
