function [cap,cap_meta]=capture_read(cap_file,cap_meta)
% function cap=capture_read(txt_cap)
% given a wireshark capture in a structure or in k12 text format (for now, maybe cooler types in future)
% divde it up into appropriate struct fields for: 
% an ETHER frame? 
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
code_path=fileparts(mfilename('fullpath'));
addpath(fullfile(code_path,'packet_asciihex'));
addpath(fullfile(code_path,'packet_bin'));
addpath(fullfile(code_path,'utils'));

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
%{
  if ~exist('cap_meta','var')
    cap_meta=struct;
  end
  %}
  cap={};
  if isstruct(cap_file)
    for sect=1:numel(cap_file)
    %{
      cap_meta(sect).header=capfile(sect).header;
      cap_meta(sect).block_count=capfile(sect).block_count;
      for i_n=1:numel(sect_meta(sect).interface)
        cap_meta(sect).interface(i_n)=capfile(sect).interface(i_n);
        cap_meta(sect).interface(i_n).packet_idx=[];
      end
    %}
      for pn=1:numel(cap_file(sect).packets)
        ef=bin2etherframe(cap_file(sect).packets(pn).data);
        try
          ipv4=bin2ipv4(ef.payload);
          ef=rmfield(ef,'payload');
        catch
          % fprintf('skipping packet %i\n',pn);
          continue;
        end
        udp=bin2udp(ipv4.payload);
        ipv4=rmfield(ipv4,'payload');
        packet=combine_struct(struct,ef, 'phy_');
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
        packet.capture_time=packet_time(cap_file(sect).packets(pn).timestamp,cap_file(sect).interface.options);
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
