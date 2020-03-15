% test_pcapngread
profile on;
%live cap test for 1 seconds
ret.s=inf;
ret.p=1000;
ret.b=inf;

% static cap test
if ~exist('live_cap','var')
  po_prof=getenv('USERPROFILE');
  cap_file=fullfile(po_prof,'\Documents\code\matlab\gta5packetcap\static_captures\GTA5WiresharkCap_20200307_first20k_gta.pcapng')
  capfile=pcapng_read(cap_file,ret);
  capfile.packet_seq
  
  pcapng_read('',ret,capfile);
  capfile.packet_seq
  pcapng_read('',ret,capfile);
  capfile.packet_seq
end

ret.s=inf;
ret.p=inf;
ret.b=1000;
if ~exist('live_cap','var')
  pcapng_read('',ret,capfile);
  capfile.packet_seq
  pcapng_read('',ret,capfile);
  capfile.packet_seq
  pcapng_read('',ret,capfile);
  capfile.packet_seq
end

ret.s=1;
ret.p=inf;
ret.b=inf;
if ~exist('live_cap','var')
  pcapng_read('',ret,capfile);
  capfile.packet_seq
  pcapng_read('',ret,capfile);
  capfile.packet_seq
  pcapng_read('',ret,capfile);
  capfile.packet_seq
end
T = profile ("info")
profexplore(T);

if exist('live_cap','var')
  p=cell(0);
  capfile=pcapng_read(cap_buf,ret);
  p{end+1}=capfile.packets;

  capfile=pcapng_read(cap_buf,ret);
  p{end+1}=capfile.packets;

end
section_count=numel(capfile.sections)


%{
packet_time(capfile(1).packets(1).timestamp,capfile(1).interface(1).options)
%sum(numel(capfile(:).interface))


ef=bin2etherframe(capfile(1).packets(1).data);
  printf('%x',ef.src)
  printf('%x',ef.dst)

ipv4=bin2ipv4(ef.payload);
ef=rmfield(ef,'payload');
udp=bin2udp(ipv4.payload);
ipv4=rmfield(ipv4,'payload');
%}
%{
curpos=ftell(input)
fseek(input,curpose,'bof')
%}