function sections=block_read(in,  ret,  sect_meta,  magic_numbers)
  % return conditions is ugly. 
  % either N seconds, or N blocks or N packets all make sense.
  %{
  ret.s=0;
  ret.p=0;
  ret.b=0;
  %}
  max_seconds=ret.s;
  max_packets=ret.p;
  max_blocks=ret.b;


  cont=fieldnames(sect_meta);
  sect_template=struct;
  sect_template.block_count=0;
  sect_template.header=struct;
  sect_template.packets=struct;
  sect_template.packets=[];
  sect_template.interface=struct;
  sect_template.interface=[];
  sections(1)=sect_template;
  sections(1)=[];
  %sect_template.id=struct;
  current_section=0;
  start_t=0;
  if numel(cont)~=0
    for current_section=1:numel(sect_meta)
      sections(current_section).block_count   =sect_meta(current_section).block_count;
      sections(current_section).header        =sect_meta(current_section).header;
      for i_n=1:numel(sect_meta(current_section).interface)
        sections(current_section).interface(i_n) =sect_meta(current_section).interface(i_n);
        sections(current_section).interface(i_n).last_packet_timestamp=  ...
            sect_meta(current_section).interface(i_n).last_packet_timestamp;
        sections(current_section).interface(i_n).packet_idx=[];
        
        if ~isfield(sections(current_section).interface(i_n),'last_packet_timestamp')
          continue;
        end
        if sections(current_section).interface(i_n).last_packet_timestamp> start_t
          [~,start_t]=packet_time(sections(current_section).interface(i_n).last_packet_timestamp,  ...
              sections(current_section).interface(i_n).options);
        end
      end
    end
  end
  delta=0;
  while ~feof(in)
    block=struct;
    block.type=fread(in,1,'uint32=>uint32');
    block.total_length=fread(in,1,'uint32=>uint32');
    if isempty(block.type)
      % another eof condition?
      return;
    end
    if block.type==3
    % 0x00000003	Simple Packet Block
      sp=block_sp(in,  magic_numbers,  block.total_length,  block.type);
      sections(current_section).packets(end+1)=sp;
      packet_idx=numel(sections(current_section).packets);
      % simple packets assume interface 0, there is a MUST in the standard.
      % dont mind my 1 vs. 0 indesing here.
      sections(current_section).interface(1).packet_idx(end+1)=packet_idx;
      clear('sp');
    elseif block.type==6
    % 0x00000006	Enhanced Packet Block
      ep=block_ep(in,  magic_numbers,  block.total_length,  block.type);
      sections(current_section).packets(end+1)=ep;
      packet_idx=numel(sections(current_section).packets);
      % get interface, and put p data on it
      sections(current_section).interface(ep.interface+1).packet_idx(end+1)=packet_idx;
      sections(current_section).interface(ep.interface+1).last_packet_timestamp=sections(current_section).packets(packet_idx).timestamp;
      if max_seconds<inf
        [~,p_time]=packet_time(sections(current_section).packets(packet_idx).timestamp,sections(current_section).interface(ep.interface+1).options);
        if start_t==0
          start_t=p_time;
        else
          delta=p_time-start_t;
        end
      end
      clear('ep');
    elseif block.type== 4
    % 0x00000004	Name Resolution Block
      error('unimplemented %x ',block.type);
    elseif block.type== 1
    %  0x00000001	Interface Description Block
      sections(current_section).interface(  ...
          numel(sections(current_section).interface)+1  )=  ...
              block_id(in,  magic_numbers,  ...
                block.total_length,  block.type);
    elseif block.type== 5
    % 0x00000005	Interface Statistics Block
      error('unimplemented %x ',block.type);
    elseif block.type== 2
    % 0x00000002	Packet Block
      error('unimplemented %x ',block.type);
    elseif block.type== 7
      error('unimplemented %x ',block.type);
    elseif block.type== 0
      % 0x00000000	Reserved ???
      error('unimplemented %x ',block.type);
    elseif block.type==hex2dec('0A0D0D0A')
      % 0x0A0D0D0A	Section Header Block
      sh=block_sh(in,  magic_numbers,  block.total_length,  block.type);
      current_section=current_section+1;
      sections(current_section)=sect_template;
      sections(current_section).header=sh;
      clear('sh');
    elseif block.type==hex2dec('00000BAD') ... 
      || block.type==hex2dec('40000BAD')
      error('cust blocks unimplemented');
      cb=block_cb(in,  block.total_length,  block.type);
    else
      db_inplace(mfilename,sprintf('unimplemented block type %x gobbling up its bits',block.type));
      %db_inplace(mfilename,sprintf('unexpected block type %i',block.type));
      block.body=fread(in,  block.total_length-8-4,  'uint8=>uint8');
    end
    block.total_length2=fread(in,1,'uint32=>uint32');
    if block.total_length ~= block.total_length2
      db_inplace(mfilename,sprintf('Corrupt block - %i in len %i, out len %i',sections(current_section).block_count, block.total_length,  ...
      block.total_length2)  );
      %error('Corrupt block - %i',sections.block_count);
    end
    sections(current_section).block_count=sections(current_section).block_count+1;
     ...
    if delta >= max_seconds...
      || sections(current_section).block_count >= max_blocks ...
      || numel(sections(current_section).packets) >= max_packets
      % end condition met, quit reading
      break;
    end
  end
  
  
end