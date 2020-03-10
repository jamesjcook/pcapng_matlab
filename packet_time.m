function human_time=packet_time(packet_time,interface_opts)
  % Convert packet timestamp to human readable text using interface opts.
  base=10;
  time_exp=6;
  if isfield(interface_opts,'if_tsresol')
    usebas2=bitget(interface_opts.if_tsresol,8);
    if usebas2
      base=2;
    end
    time_exp=bitset(interface_opts.if_tsresol,8,0);
  end
  % 6 is microsecond resolution. 
  time_res_factor=double(base)^(-double(time_exp));
  
  if isfield(interface_opts,'if_tzone')
    error('if_tzone not implemented');
  end
  if isfield(interface_opts,'if_fcslen')
      error('if_fcslen not implemented');
  end
  if isfield(interface_opts,'if_tsoffset')
      error('if_tsoffset not implemented');
  end
  % drop time_res_factor of digits off timestamp, then treat as normal, 
  % eg, epoc 1970-01-01 00:00:00 time.
  seconds=floor(packet_time*time_res_factor);
  ms=packet_time-seconds;
  % timely in str format strftime('%c',gmtime(seconds))
  datestr(packet_time,30)
  %gmtime (t)
end
