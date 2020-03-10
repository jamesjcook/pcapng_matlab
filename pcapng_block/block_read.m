
function sections=block_read(input,  magic_numbers)
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
  while ~feof(input)
    block=struct;
    block.type=fread(input,1,'uint32=>uint32');
    block.total_length=fread(input,1,'uint32=>uint32');
    if block.type==3
    % 0x00000003	Simple Packet Block
      sp=block_sp(input,  magic_numbers,  block.total_length,  block.type);
      % get interface and put the sp on it
      sections(current_section).packets(end+1)=sp;
      packet_idx=numel(sections(current_section).packets);
      % simple packets assume interface 0, there is a MUST in the standard.
      % dont mind my 1 vs. 0 indesing here.
      sections(current_section).interface(1).packet_idx(end+1)=packet_idx;
      clear('sp');
    elseif block.type==6
    % 0x00000006	Enhanced Packet Block
      ep=block_ep(input,  magic_numbers,  block.total_length,  block.type);
      sections(current_section).packets(end+1)=ep;
      packet_idx=numel(sections(current_section).packets);
      sections(current_section).interface(ep.interface+1).packet_idx(end+1)=packet_idx;
      clear('ep');
      % get interface, and put sp data on it
    elseif block.type== 4
    % 0x00000004	Name Resolution Block
      error('unimplemented %x ',block.type);
    elseif block.type== 1
    %  0x00000001	Interface Description Block
      sections(current_section).interface(  ...
          numel(sections(current_section).interface)+1  )=  ...
              block_id(input,  magic_numbers,  ...
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
      sh=block_sh(input,  magic_numbers,  block.total_length,  block.type);
      current_section=current_section+1;
      sections(current_section)=sect_template;
      sections(current_section).header=sh;
      clear('sh');
    elseif block.type==hex2dec('00000BAD') ... 
      || block.type==hex2dec('40000BAD')
      error('cust blocks unimplemented');
      cb=block_cb(input,  block.total_length,  block.type);
    else
      db_inplace(mfilename,sprintf('unimplemented block type %x gobbling up its bits',block.type));
      %db_inplace(mfilename,sprintf('unexpected block type %i',block.type));
      block.body=fread(input,  block.total_length-8-4,  'uint8=>uint8');
    end
    block.total_length2=fread(input,1,'uint32=>uint32');
    if block.total_length ~= block.total_length2
      db_inplace(mfilename,sprintf('Corrupt block - %i input len %i, out len %i',sections.block_count, block.total_length,block.total_length2));

      %error('Corrupt block - %i',sections.block_count);
    end
    sections(current_section).block_count=sections(current_section).block_count+1;
  end
  
  
end