
use_profile=0;
live_cap=1;
% fork_test=1;
% cant fork in gui.
global cap;
global ret;
% clear live_cap;

% test_pcapngread
if use_profile
profile off; profile clear;
profile on;
end
%live cap_in test for 1 seconds
ret.s=1;
ret.p=inf;
ret.b=inf;

% static cap_in test
if ~exist('live_cap','var')
  po_prof=getenv('USERPROFILE');
  cap_file=fullfile(po_prof,'\Documents\code\matlab\gta5packetcap\static_captures\GTA5WiresharkCap_20200307_first20k_gta.pcapng')
  cap_in=cap_file;
end
if exist('live_cap','var')
  cap_in=cap_buf;
end
%%
cap=pcapng_read(cap_in,ret);
cap.packet_seq

pcapng_read(cap_in,ret,cap);
cap.packet_seq
pcapng_read(cap_in,ret,cap);
cap.packet_seq

%{
if fork_test
  fprintf('forking off');
  [child_proc,msg]=fork()
end
%}

 
%if child_proc==0
%  fprintf('Child Processing\n');
%%
ret.s=inf;
ret.p=inf;
ret.b=1000;
pcapng_read(cap_in,ret,cap);
cap.packet_seq
pcapng_read(cap_in,ret,cap);
cap.packet_seq
pcapng_read(cap_in,ret,cap);
cap.packet_seq
%%
ret.s=inf;
ret.p=1000;
ret.b=inf;
pcapng_read(cap_in,ret,cap);
cap.packet_seq
pcapng_read(cap_in,ret,cap);
cap.packet_seq
pcapng_read(cap_in,ret,cap);
cap.packet_seq
%  quit;
%end
%%
%{
  p=cell(0);
  cap=pcapng_read(cap_buf,ret);
  p{end+1}=cap.sections.packets;

  cap=pcapng_read(cap_buf,ret);
  p{end+1}=cap.sections.packets;
%}

%fprintf('Waiting for child\n');
%waitpid(child_proc);
section_count=numel(cap.sections)
if use_profile
T = profile ("info")
profexplore(T);
end

%{

    if ~exist('cap_in','var')
      packet_skip=0;
      cap_in=pcapng_read(cap_buf,ret);
    else
      % wait for last bg capture
    end
    packet_stop=cap_in.packet_seq;
%}