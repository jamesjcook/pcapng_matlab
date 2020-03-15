classdef pcapng <handle
  properties (Constant = true )
    magic_numbers=struct('endian',hex2dec('1A2B3C4D'));
    % cant imply a struct when doing constantant.
    %magic_numbers.endian=hex2dec('1A2B3C4D');
    section_template=struct('header',struct,...
        'interface',struct([]),...
        'packets',struct([])  );
  end
  properties (Access = private)
    Data
  end
  properties
    % the input handle we're reading from
    in
    % each section of the file. A structure. 
    sections=struct([]);
    current_section=zeros(0,'uint64');
    block_count=zeros(0,'uint64');
    % packet_seq is incremented foreach packet.
    % its a count of how many packets in this capture. 
    % sections have similar value
    packet_seq=zeros(0,'uint64');
    % dns will be a container.Map holding of HEX_ip -> name_res info. or should it be ipstrings?
    dns=containers.Map('KeyType', 'char', 'ValueType', 'char');
    % timestamp of last packet in seconds. 
    t_last_packet=zeros(1,'double');
  end
  methods
    function obj = pcapng(in)
      if nargin==1
        obj.in=in;0
      end
%      if nargin > 0
%        obj.Prop = val;
%      end
    obj.sections(1)=pcapng.section_template;
    obj.sections(1)=[];
    % how many packets in this capture. 
    obj.block_count=0;
    obj.packet_seq=0;
    obj.current_section=0;

    end
  end
end
