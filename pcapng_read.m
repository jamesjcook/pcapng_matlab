function sections=pcapng_read(in)
% Per spec at http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=
% https://raw.githubusercontent.com/pcapng/pcapng/master/
% draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/
% ascii&type=ascii#rfc.section.3
% Here is general format.
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
code_path=fileparts(mfilename('fullpath'));
addpath(fullfile(code_path,'pcapng_block'));
addpath(fullfile(code_path,'utils'));
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

%{
In memory lets organize things neatishly, like
interface->packets
interface->stats
ips->nslookup
That means tearing our structure apart a bit.
%}
  if ~is_valid_file_id(in) && exist(in,'file')
    in=fopen(in);
  end

  if exist('blk_type_enumerate','var')
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
  % not sure how to effectivly share all the magic numbers.... 
  magic_numbers.endian=hex2dec('1A2B3C4D');
  sections=block_read(in,magic_numbers);
  % should this just  be the "packet" stream?  Or should we be a pcapng struct in memory after some fashion?
  
  return;

end
