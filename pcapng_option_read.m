function opt=pcapng_option_read(in,octet_length,block_type)
  % temporary opt short circuit due to glitcheroonies.
  %opt=fread(in,octet_length,'uint8=>uint8');
  %return;
  opt=struct;
  octets_consumed=0;
  opt.endofopt=0;
  while octets_consumed< octet_length && ~opt.endofopt
    opt_code=fread(in,1,'uint16=>uint16');
    opt_length=fread(in,1,'uint16=>uint16');
    octets_consumed=octets_consumed+4;
    opt_tail=char_alignment(opt_length);
    if opt_code==0
      opt.endofopt=1;
    elseif opt_code==1
      opt.comment=sprintf('%s',fread(in,opt_length,'char=>char'));
    %elseif opt_code==2573
    %  error('opt 2573');
      % unknown option, not in docs. 
    %  opt.x_2673=fread(in,opt_length,'uint8');
    elseif opt_code==2988
      opt.str=sprintf('%s',fread(in,opt_length,'char=>char'));
    elseif opt_code==2989
      opt.bin=fread(in,opt_length,'uint8=>uint8');
    elseif opt_code==19372
      opt.str_priv=sprintf('%s',fread(in,opt_length,'char=>char'));
    elseif opt_code==19373
      opt.bin_priv=fread(in,opt_length,'uint8=>uint8');
    elseif block_type==hex2dec('0A0D0D0A')
      %%%% SHB
      if opt_code==2
        opt.shb_hardware=sprintf('%s',fread(in,opt_length,'char=>char'));
      elseif opt_code==3
        opt.shb_os=sprintf('%s',fread(in,opt_length,'char=>char'));
      elseif opt_code==4
        opt.shb_userappl=sprintf('%s',fread(in,opt_length,'char=>char'));
      else
        error('opt %i unrecognized, blk %x',opt_code,block_type);
      end
    elseif block_type==6 ||block_type==2
      %%%% EPB/PB
      if opt_code==2
        opt.epb_flags=fread(in,1,'uint32=>uint32');
        % 0-1 00 unkn, 01 inbound, 10 outbound
        dir=bitget(opt.epb_flags(1:2));
        if dir==2
          opt.dir='out'
        elseif dir==1
          opt.dir='in';
        elseif dir==0
          opt.dir='unk';
        else
          error('epbflag direction flag invalid');
        end
        % 2-4 0 unkn, 001 unit, 010 multi-cast, 011 broadcast, 100 promisc(snoopy)
        rec=bitget(opt.epb_flags,3:5);
        if rec==0
          opt.epb_reception='unspecified';
        elseif rec==1
          opt.epb_reception='unicast';
        elseif rec==2
          opt.epb_reception='multicast';
        elseif rec==3
          opt.epb_reception='broadcast';
        elseif rec==4
          opt.epb_reception='promiscuous';
        else
          error('reception type err');
        end
        % 5-8 fcs len 0 unavail
        opt.fcs_len=bigget(opt.epb_flags,6:9);
        % 9-15 alwys 0
        res=bitget(opt.epb_flags,10:16);
        if res ~=0
          error('epb reserved corrpution');
        end
        % 16-31 link layer errs 
        % 31 symbol, 
        opt.epb_err.symbol=bitget(opt.epb_flags,32);
        % 30 preable, 
        opt.epb_err.preamble=bitget(opt.epb_flags,31)
        % 29 start frame, 
        opt.epb_err.frame_st_delim=bitget(opt.epb_flags,30)
        % 28 unalign frame, 
        opt.epb_err.frame_misalign=bitget(opt.epb_flags,29)
        % 27 wrong inter frame gap
        opt.epb_err.frame_wrong_inter_gap=bitget(opt.epb_flags,28)
        % 26 packet too short
        opt.epb_err.packet_too_short=bitget(opt.epb_flags,27)
        % 25 packet too long
        opt.epb_err.packet_too_long=bitget(opt.epb_flags,26)
        % 24 crc
        opt.epb_err.crc_error=bitget(opt.epb_flags,25)
      elseif opt_code==3
        opt.epb_hash=fread(in,opt_length,'uint8=>uint8');
        if opt.epb_hash(1)==0
          opt.epb_hash_alg='2s compliment';
        elseif opt.epb_hash(1)==1
          opt.epb_hash_alg='XOR';
        elseif opt.epb_hash(1)==2
          opt.epb_hash_alg='CRC32';
        elseif opt.epb_hash(1)==3
          opt.epb_hash_alg='MD-5';
        elseif opt.epb_hash(1)==4
          opt.epb_hash_alg='SHA-1';
        elseif opt.epb_hash(1)==5
          opt.epb_hash_alg='Toeplitz';
        else
          error('Unrecognized packet hash algorithm');
        end
      elseif opt_code==4
        opt.epb_dropcount=fread(in,1,'uint64=>uint64');
      else
        error('opt %i unrecognized, blk %x',opt_code,block_type);
      end
    elseif block_type==1
      %%%% IDB
      if opt_code==2
        opt.if_name=sprintf('%s',fread(in,opt_length,'char=>char'));
      elseif opt_code==3
        opt.if_description=sprintf('%s',fread(in,opt_length,'char=>char'));
      elseif opt_code==4
        if_IPv4addr=fread(in,opt_length,'uint8=>uint8');
        if isfield(opt,'if_IPv4addr')
          opt.if_IPv4addr=[opt.if_IPv4addr;if_IPv4addr];
        else
          opt.if_IPv4addr=if_IPv4addr;
        end
      elseif opt_code==5
        if_IPv6addr=fread(in,opt_length,'uint8=>uint8');
        if isfield(opt,'if_IPv6addr')
          opt.if_IPv6addr=[opt.if_IPv6addr;if_IPv6addr];
        else
          opt.if_IPv6addr=if_IPv6addr;
        end
      elseif opt_code==6
        opt.if_MACaddr=fread(in,opt_length,'uint8=>uint8');
      elseif opt_code==7
        opt.if_EUIaddr=fread(in,opt_length,'uint8=>uint8');
      elseif opt_code==8
        opt.if_speed=fread(in,1,'uint64=>uint64');
      elseif opt_code==9
        opt.if_tsresol=fread(in,opt_length,'uint8=>uint8');
      elseif opt_code==10
        opt.if_tzone=fread(in,opt_length,'uint8=>uint8');
      elseif opt_code==11
        opt.if_filter=fread(in,opt_length,'uint8=>uint8');
      elseif opt_code==12
        opt.if_os=sprintf('%s',fread(in,opt_length,'char=>char'));
      elseif opt_code==13
        opt.if_fcslen=fread(in,opt_length,'uint8=>uint8');
      elseif opt_code==14
        opt.if_tsoffset=fread(in,1,'uint64=>uint64');
      elseif opt_code==15
        opt.if_hardware=sprintf('%s',fread(in,opt_length,'char=>char'));
      else
        error('opt %i unrecognized, blk %x',opt_code,block_type);
      end
    elseif block_type==5
      %%% ISB
      if opt_code==2
        opt.isb_starttime=timestamp_read(in);
      elseif opt_code==3
        opt.isb_endtime=timestamp_read(in);
      elseif opt_code==4
        opt.isb_ifrecv=fread(in,1,'uint64=>uint64');
      elseif opt_code==5
        opt.isb_ifdrop=fread(in,1,'uint64=>uint64');
      elseif opt_code==6
        opt.isb_filteraccept=fread(in,1,'uint64=>uint64');
      elseif opt_code==7
        opt.isb_osdrop=fread(in,1,'uint64=>uint64');
      elseif opt_code==8
        opt.isb_usrdeliv=fread(in,1,'uint64=>uint64');
      else
        error('opt %i unrecognized, blk %x',opt_code,block_type);
      end
    else
      error('opt %i unrecognized, blk %x',opt_code,block_type);
    end
    scrap=fread(in,opt_tail,'uint8');
    octets_consumed=octets_consumed+opt_length+opt_tail;
  end
  if octets_consumed~=octet_length
    error('Option length err! Used %i of %i bytes',octets_consumed,octet_length);
  end
   
  
end

