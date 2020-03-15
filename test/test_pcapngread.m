% test_pcapngread
%{ 
% static cap test
po_prof=getenv('USERPROFILE');
cap_file=fullfile(po_prof,'\Documents\code\matlab\gta5packetcap\cap_buffer\ring_00000_20200306231659.pcapng')
%}

%live cap test for 4 seconds

capfile=struct;

ret.s=1
ret.p=inf;
ret.b=inf;
p=cell(0);

capfile=pcapng_read(cap_buf,ret,capfile);
p{end+1}=capfile.packets;

capfile=pcapng_read(cap_buf,ret,capfile);
p{end+1}=capfile.packets;

section_count=numel(capfile)


%{
cap=capture_read(capfile)
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