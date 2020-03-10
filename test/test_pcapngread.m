% test_pcapngread

cap_file='C:\Users\Diablo\Documents\code\matlab\gta5packetcap\cap_buffer\ring_00000_20200306231659.pcapng';

capfile=pcapng_read(cap_file);
section_count=numel(capfile)
packet_time(capfile(1).packets(1).timestamp,capfile(1).interface(1).options)
%sum(numel(capfile(:).interface))
%{
curpos=ftell(input)
fseek(input,curpose,'bof')
%}