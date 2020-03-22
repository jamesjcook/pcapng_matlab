function offset=char_alignment(data_length,bytes)
  % for handling the 32-bit word alignment(or any other alignment via the bytes var).
  if ~exist('bytes','var')
    bytes=4;
  end
  over_len=mod(data_length,bytes);
  offset=0;
  if over_len>=1
    offset=bytes-over_len;
  end
end