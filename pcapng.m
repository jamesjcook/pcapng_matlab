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
    % packet_seconds is like packet seq, except with seconds. 
    % by definition it will be the number of used entries in second index. 
    % we'd get cute using the length of second index and auto expanding it, but 
    % that is somewhat expensive.
    packet_seconds=zeros(1,'uint64');
    % Second_index is the boundaries (in packet_seq), for each second.
    % In practical use for live capture application, and not otherwise.
    % This will be the packet_seq number of the final packet in the previous second.
    % going to cap out at 3 hours for the time being.
    % matlab doesnt like this in here like this ... oh whell.
    % three_hrs_of_seconds=3*60*60;
    second_index=zeros([1,3*60*60],'int64');
    % dns will be a container.Map holding of HEX_ip -> name_res info. or should it be ipstrings?
    dns=containers.Map('KeyType', 'char', 'ValueType', 'char');
    % timestamp of last packet in seconds.
    t_last_packet=zeros(1,'double');
    % to hold onto read state if we manage to make asynchronous work
    %data_ready=zeros(0,'uint64');
    %packet_seq_last=zeros(0,'uint64');
  end
  methods
    function obj = pcapng(in)
      if nargin==1
        obj.in=in;
      end
%      if nargin > 0
%        obj.Prop = val;
%      end
      obj.sections(1)=pcapng.section_template;
      obj.sections(1)=[];
      obj.current_section=0;
      obj.block_count=0;
      % how many packets in this capture. 
      obj.packet_seq=0;
      obj.second_index=obj.second_index-1;
    end
  end
end
