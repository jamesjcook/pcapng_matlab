function cap=capture_read(cap_file,packet_skip,packet_stop)
% function cap=capture_read(capture)
% function cap=capture_read(cap_file,packet_skip,packet_stop)
% given a wireshark capture in a data structure as returned by pcapng_read, or 
% in k12 text format (for now, maybe cooler types in future)
% optionally give packet skip and stop to jump N packets into he file, and stop 
% at some index.
% Only simple pcapng's suppoite currently
% 
% load divde it up into appropriate struct fields for: 
% ethernet frame 
% + ipv4 
% + udp packet.
% 
% grand ip packet docs here 
% http://tracesplay.sourceforge.net/help.html
% 
% returns cell array of packets structures. 
% (Sorry wasn't cool enough to craft a struct array.)
%

% code trailing:D 

%{
k12 text capture example, no attempt to validate against official docs, just the output of wireshark. Ex of two packets in following block comment
%}
%{
+---------+---------------+----------+
01:23:45,678,901   ETHER
|0   |aa|aa|aa|aa|aa|aa|bb|bb|bb|bb|bb|bb|08|00|45|00|00|51|7b|19|00|00|80|11|00|00|cc|cc|cc|cc|dd|dd|dd|dd|ee|ee|ff|ff|11|11|00|00|00|04|de|ad|

+---------+---------------+----------+
01:23:46,678,901   ETHER
|0   |aa|aa|aa|aa|aa|aa|bb|bb|bb|bb|bb|bb|08|00|45|00|00|51|7b|19|00|00|80|11|00|00|cc|cc|cc|cc|dd|dd|dd|dd|ee|ee|ff|ff|11|11|00|00|00|04|be|ef|

%}
%{
 expected ouput 

cap =
{
  [1,1] =

    scalar structure containing the fields:

      phy_dst = aaaaaaaaaaaa
      phy_src = bbbbbbbbbbbb
      phy_type = 0800
      ip_version = 4
      ip_IHL = 5
      ip_DSCP = 0
      ip_ECN = 0
      ip_total_length = 81
      ip_id = 7b19
      ip_flags = 0
      ip_fragment_offset = 0
      ip_TTL = 128
      ip_protocol = 17
      ip_cksum = 0000
      ip_src = 204.204.204.204
      ip_dst = 221.221.221.221
      udp_srcport = 61166
      udp_dstport = 65535
      udp_length = 4369
      udp_checksum = 0
      udp_payload = 0004dead
      capture_time = 01:23:45,678,901   ETHER

  [1,2] =

    scalar structure containing the fields:

      phy_dst = aaaaaaaaaaaa
      phy_src = bbbbbbbbbbbb
      phy_type = 0800
      ip_version = 4
      ip_IHL = 5
      ip_DSCP = 0
      ip_ECN = 0
      ip_total_length = 81
      ip_id = 7b19
      ip_flags = 0
      ip_fragment_offset = 0
      ip_TTL = 128
      ip_protocol = 17
      ip_cksum = 0000
      ip_src = 204.204.204.204
      ip_dst = 221.221.221.221
      udp_srcport = 61166
      udp_dstport = 65535
      udp_length = 4369
      udp_checksum = 0
      udp_payload = 0004beef
      capture_time = 01:23:46,678,901   ETHER

}
%}
  if ~exist('packet_skip','var')
    packet_skip=0;
  end
  cap={};
  if isa(cap_file,'pcapng')
    for sect=1:numel(cap_file)
      if ~exist('packet_stop','var')||packet_stop<=0 ||packet_stop==inf ...
        || packet_stop> numel(cap_file.sections(sect).packets)
        packet_stop=numel(cap_file.sections(sect).packets)
      end
      for pn=1+packet_skip:packet_stop
        ef=bin2etherframe(cap_file.sections(sect).packets(pn).data);
        try
          % ipv4 should follow the same pattern as ipv6, but we dont have to because a value of 8 comes in very low.
          if ef.type==[08;00]
            ip=bin2ipv4(ef.payload);
          elseif ef.type==[ hex2num('86','uint8');  hex2num('dd','uint8') ]
          end
        catch
          % fprintf('skipping packet %i\n',pn);
          % ipv4=[];
          continue;
        end
        % udp is 17
        if ip.protocol==17
          udp=bin2udp(ip.payload);
        %ipv4=rmfield(ip,'payload');
        end
        % to avoid combine struct which sums up to significant runtime eventually, 
        % we'll hard code the combine struct operation. The fields are constant anyway.
        %phy_fields={'dst','src','type'};
        %ip_fields={'version', 'IHL', 'DSCP', 'ECN', 'total_length', 'id', 'flags', 'fragment_offset', 'TTL', 'protocol','cksum', 'src', 'dst'};
        %upd_fields={'srcport', 'dstport', 'length', 'checksum'};
        
        packet=struct('phy_dst',ef.dst,'phy_src',ef.src,'phy_type',ef.type, ...
                      'ip_version',ip.version,'ip_IHL',ip.IHL,'ip_DSCP',ip.DSCP, ...
                      'ip_ECN',ip.ECN,'ip_total_length',ip.total_length, ...
                      'ip_id',ip.id,'ip_flags',ip.flags, ... 
                      'ip_fragment_offset',ip.fragment_offset,'ip_TTL',ip.TTL, ...
                      'ip_protocol',ip.protocol,'ip_cksum',ip.cksum,...
                      'ip_src',ip.src,'ip_dst',ip.dst,...
                      'udp_srcport',udp.srcport,'udp_dstport',udp.dstport,...
                      'udp_length',udp.length,'udp_checksum',udp.checksum, ...
                      'payload',udp.payload  );
        
      
        packet.capture_time=packet_time(cap_file.sections(sect).packets(pn).timestamp,cap_file.sections(sect).interface.options);
        cap{end+1}=packet;
      end
    end
  else
  pack_sep='+---------+---------------+----------+';
  fid = fopen(txt_cap);
  onCleanup(@() fclose(fid));
  dstlineidx = 0;
  packet='';
  while (~feof(fid))
    linestr = fgetl(fid);
    % four line types, separator, timestamply, and packet, blanks separating the grouping.
    if isempty(linestr) 
      packet='';
      continue;
    end
    if strcmp(pack_sep,linestr)
      ts_line= fgetl(fid);
      packet = fgetl(fid);
      
      packet=strsplit(packet,'|');
      % all first entry are '0   ', not sure why.
      % just skipping for the time being.
      phy =hex2phy(strjoin(packet(3:end),''));
      
      % 0800 is magic number for ipv4 from the phy layer
      % 86dd is magic number for ipv6 from the phy layer
      % would be better to call this transport than ipv4...?
      % 
      if ~strcmp(phy.type,'0800')
        if strcmp(phy.type,'86dd')
          warning('ipv6 unimplemented');
          clear('ipv4');
          clear('udp');
        else
          error('unrecognized payload type at phy? layer');
        end
      else
        ipv4=hex2ipv4(phy.payload,'helpful',0);
        phy =rmfield(phy,'payload');
      end
      
      if exist('ipv4','var')
        % udp is 17
        if ipv4.protocol==17
          udp =hex2udp(ipv4.payload,'dec');
          ipv4=rmfield(ipv4,'payload');
        else
          warning('only udp implemented');
          clear('udp');
        end
      end
      
      packet=combine_struct(struct,phy, 'phy_');
      if exist('ipv4','var')
        packet=combine_struct(packet,ipv4,'ip_');
      elseif exist('ipv6','var')
        packet=combine_struct(packet,ipv6,'ip_');
      else
        
      end
      if exist('udp','var')
        packet=combine_struct(packet,udp, 'udp_');
      elseif exist('tcp','var')
        packet=combine_struct(packet,tcp, 'udp_');
      else
      end
      packet.capture_time=ts_line;
      cap{end+1}=packet;
    end
    end
  end

return;
