function capfile=pcapng_read(in,ret,capfile)
  % returns after first return condition is met, (b)lock, (s)econds, (p)ackets.
  % input is either open app/file handle or path to static file to read.
  % Returns the logical block hierarchy like the spec talks of.
  % We can elect to continute reading after we stop by calling again, 
  % that will update the data structure internal to the function. 
  %
  % I should test the persistenc thing by allocating a large rand array. 
  % External to this function we should only be reading parts of the cap file, 
  % not updating it. In theory, that should mean no replicates.
  
  %ret.p=inf;
  %ret.s=1;
  % blocks seems very similar to packets...
  %ret.b=10; 
  % return conditions is ugly. 
  % either N seconds, or N blocks or N packets all make sense.
  %{
  ret.s=0;
  ret.p=0;
  ret.b=0;
  %}
  
debugging=0;
% Per spec at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=
% https://raw.githubusercontent.com/pcapng/pcapng/master/
% draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/
% ascii&type=ascii#rfc.section.3
% Here is general format.
if 0  % doc block
%{
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Block Type                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Block Total Length                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                          Block Body                           /
/              variable length, padded to 32 bits               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Block Total Length                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%}

%{
Section Header
|
+- Interface Description
|  +- Simple Packet
|  +- Enhanced Packet
|  +- Interface Statistics
|
+- Name Resolution
%}

% With this idea of logical dumpfile hierarchy, 
% lets make a capfile a struct with capfile and name resolutions.
% capfile are an array of structs
% section structs have an array of interface structs, packets. 

%{
EX, 
capfile.name_res_map.hexip.?
capfile.sections(1).interface(1).packets?
capfile.sections(1).interface(1).stats
capfile.sections(1).interface(2).
capfile.sections(1).interface(1).stats
capfile.sections(2).interface(1).
capfile.sections(2).interface(2).
capfile.packet_seq 
capfile.block_count
capfile.packet_seconds
capfile.second_index
capfile.t_last_packet
%}
end
  cleaner={};
  % Maybe in should be moved into the capfile object?
  if ~isnumeric(in)&& ~exist('capfile','var')
    if exist(in,'file')
      in=fopen(in);
      %cleaner{end+1} = onCleanup(@() fclose(in));
    else
      error('misisng %s',in);
    end
  end

  if 0 % doc block of block types
    
%{
block type registry 
0x00000000	Reserved ???
0x00000001	Interface Description Block
0x00000002	Packet Block
0x00000003	Simple Packet Block
0x00000004	Name Resolution Block
0x00000005	Interface Statistics Block
0x00000006	Enhanced Packet Block
0x00000007	IRIG Timestamp Block (requested by Gianluca Varenni 
    <gianluca.varenni@cacetech.com>, CACE Technologies LLC); 
    code also used for Socket Aggregation Event Block
0x00000008	ARINC 429 in AFDX Encapsulation Information Block 
    (requested by Gianluca Varenni <gianluca.varenni@cacetech.com>, 
      CACE Technologies LLC)
0x00000009	systemd Journal Export Block
0x0000000A	Decryption Secrets Block
0x00000101	Hone Project Machine Info Block (see also Google version)
0x00000102	Hone Project Connection Event Block (see also Google version)
0x00000201	Sysdig Machine Info Block
0x00000202	Sysdig Process Info Block, version 1
0x00000203	Sysdig FD List Block
0x00000204	Sysdig Event Block
0x00000205	Sysdig Interface List Block
0x00000206	Sysdig User List Block
0x00000207	Sysdig Process Info Block, version 2
0x00000208	Sysdig Event Block with flags
0x00000209	Sysdig Process Info Block, version 3
0x00000210	Sysdig Process Info Block, version 4
0x00000211	Sysdig Process Info Block, version 5
0x00000212	Sysdig Process Info Block, version 6
0x00000213	Sysdig Process Info Block, version 7
0x00000BAD	Custom Block that rewriters can copy into new files
0x40000BAD	Custom Block that rewriters should not copy into new files
0x0A0D0D0A	Section Header Block

Used to detect trace files corrupted because of file transfers using the HTTP
0x0A0D0A00-0x0A0D0AFF	Reserved. 
0x000A0D0A-0xFF0A0D0A	Reserved. 
0x000A0D0D-0xFF0A0D0D	Reserved.
0x0D0D0A00-0x0D0D0AFF	Reserved. 

0x80000000-0xFFFFFFFF	
%}
  end
  max_seconds=ret.s;
  max_packets=ret.p;
  max_blocks=ret.b;

  if ~exist('capfile','var') || ~isa(capfile,'pcapng')
    capfile=pcapng(in);
  else
    in=capfile.in;
  end
  
  t_delta=0;
  t_start=0;
  t_read=tic;
  start_packet=capfile.packet_seq;
  start_block=capfile.block_count;
  curs=capfile.current_section;
  while ~feof(in)
    block=struct;
    block.type=fread(in,1,'uint32=>uint32');
    if isempty(block.type)
      % another eof condition?
      break;
    end
    block.total_length=fread(in,1,'uint32=>uint32');
    if block.type==6
    % 0x00000006	Enhanced Packet Block
      ep=block_ep(in,  block.total_length,  block.type);
      capfile.sections(curs).packets(end+1)=ep;
      capfile.packet_seq=capfile.packet_seq+1;
      % get interface, and put p data on it
      capfile.sections(curs).interface(ep.interface+1).packet_idx(end+1)=capfile.packet_seq;
      if max_seconds<inf
        [~,t_packet]=packet_time(capfile.sections(curs).packets(end).timestamp,capfile.sections(curs).interface(ep.interface+1).options);

        if t_start==0
          t_start=t_packet;
        else
          t_delta=t_packet-t_start;
        end
      end
      if debugging>50
        clear('ep');
      end
    elseif block.type==3
    % 0x00000003	Simple Packet Block
      sp=block_sp(in,  block.total_length,  block.type,  capfile.magic_numbers);
      capfile.sections(curs).packets(end+1)=sp;
      capfile.packet_seq=capfile.packet_seq+1;
      % simple packets assume interface 0, there is a MUST in the standard.
      % dont mind my 1 vs. 0 indesing here.
      capfile.sections(curs).interface(1).packet_idx(end+1)=capfile.packet_seq;
      if debugging>50
        clear('sp');
      end
    elseif block.type== 2
    % 0x00000002	Packet Block
      error('unimplemented %x ',block.type);
    elseif block.type== 1
    %  0x00000001	Interface Description Block
      capfile.sections(curs).interface(  ...
          numel(capfile.sections(curs).interface)+1  )=  ...
              block_id(in,  block.total_length,  block.type);
    elseif block.type== 5
    % 0x00000005	Interface Statistics Block
      is=block_is(in,  block.total_length,  block.type);
      capfile.sections(curs).interface(is.interface+1).stats=is;
      %error('unimplemented %x ',block.type);
    elseif block.type== 4
    % 0x00000004	Name Resolution Block
      error('unimplemented %x ',block.type);
    elseif block.type== 7
    % 0x00000007	IRIG Timestamp Block (requested by Gianluca Varenni 
    %     <gianluca.varenni@cacetech.com>, CACE Technologies LLC); 
    %     code also used for Socket Aggregation Event Block
      error('unimplemented %x ',block.type);
    elseif block.type== 0
      % 0x00000000	Reserved ???
      error('unimplemented %x ',block.type);
    elseif block.type==hex2dec('0A0D0D0A')
      % 0x0A0D0D0A	Section Header Block
      sh=block_sh(in,  block.total_length,  block.type,  capfile.magic_numbers);
      curs=curs+1;
      capfile.current_section=curs;
      capfile.sections(curs)=capfile.section_template;
      capfile.sections(curs).header=sh;
      if debugging>50
        clear('sh');
      end
    elseif block.type==hex2dec('00000BAD') ... 
      || block.type==hex2dec('40000BAD')
      error('cust blocks unimplemented');
      cb=block_cb(in,  block.total_length,  block.type);
    else
      % db_inplace(mfilename,sprintf('unimplemented block type %x gobbling up its bits',block.type));
      error(sprintf('unimplemented block type %x gobbling up its bits',block.type));
      %db_inplace(mfilename,sprintf('unexpected block type %i',block.type));
      block.body=fread(in,  block.total_length-8-4,  'uint8=>uint8');
    end
    block.total_length2=fread(in,1,'uint32=>uint32');
    if block.total_length ~= block.total_length2
      db_inplace(mfilename,sprintf('Corrupt block - %i in len %i, out len %i',capfile.block_count, block.total_length,  ...
      block.total_length2)  );
      %error('Corrupt block - %i',capfile.block_count);
    end
    
    % should this just  be the "packet" stream?  Or should we be a pcapng struct in memory after some fashion?
    capfile.block_count=capfile.block_count+1;
    funct_time=toc(t_read);
    if funct_time>=max_seconds && funct_time> t_delta
      warning('packet delta over ridden by funct, %f <- %f',t_delta,funct_time);
      t_delta=funct_time;
    end
    if t_delta >= max_seconds...
      ||capfile.block_count -start_block >= max_blocks ...
      ||capfile.packet_seq -start_packet >= max_packets
      if (t_delta>=max_seconds) 
        capfile.packet_seconds=capfile.packet_seconds+1;
        %{
        fprintf('return tripped(%i) .. %0.2f >= %i \n', ... 
                 capfile.packet_seconds,t_delta,max_seconds);
        %}
        % this is only in effect if we're using seconds to gate our return. 
        % that should leave both of these at zero the rest of the time. 
        capfile.second_index(capfile.packet_seconds)=capfile.packet_seq-1;
      end
      % end condition met, quit reading
      break;
    end
    t_delta=0;
  end

  for sect=1:curs
    for i_iface=1:numel(capfile.sections(sect).interface)
      if numel(capfile.sections(sect).packets)==0
        break;
      end
      capfile.sections(sect).interface(i_iface).last_packet_timestamp=capfile.sections(sect).packets(end).timestamp;
      [~,t_packet]=packet_time(capfile.sections(sect).interface(i_iface).last_packet_timestamp, ...
          capfile.sections(sect).interface(i_iface).options);
      if t_packet>capfile.t_last_packet
        capfile.t_last_packet=t_packet;
      end
    end
  end
  

  return;

end
