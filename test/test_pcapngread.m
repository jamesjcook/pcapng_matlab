% test_pcapngread

cap_file='C:\Users\Diablo\Documents\code\matlab\gta5packetcap\cap_buffer\ring_00000_20200306231659.pcapng';

capfile=pcapng_read(cap_file);


curpos=ftell(input)
fseek(input,curpose,'bof')