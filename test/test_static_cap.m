%{ 
fclose all; clear all; close all; clc; 
%}
% Test the remote_db_update by running the paired functions slurping one second at a time.
% Useful for benchmark testing since we can't really do that asynchronosouly. 
run(fullfile(getenv('USERPROFILE'), 'Documents\code\matlab\gta5packetcap\path_set.m'));
filtered_sim = fullfile(getenv('USERPROFILE'), 'Documents\code\matlab\gta5packetcap\static_captures\GTA5WiresharkCap_20200322_gta.pcapng');

use_profile=1;
cap_handle=fopen(filtered_sim,'r');
ret.s=1;
ret.p=inf;
ret.b=inf;
%%
cap=pcapng_read(cap_handle,ret);

print_limit=8;
time_limit=3*60*60;
history_len=45;
avg_field={'byte_rate','byte_send_rate'};
cap_action = fullfile(getenv('USERPROFILE'), 'Documents\code\matlab\gta5packetcap\cap_action');
local_ip=ip_conv('192.168.1.118','ip2dec');
%%
remote_db_update(cap, print_limit,  time_limit,...
    local_ip,  history_len,  avg_field, cap_action);
    
if use_profile
  profile off; profile clear;
  profile on;
end

for r=1:400
  %clc;
  cap=pcapng_read(cap_handle,ret,cap);
  remote_db_update();
end
%db_inplace(mfilename,'testing r2');
for r=1:5
  cap=pcapng_read(cap_handle,ret,cap);
  remote_db_update();
end
fclose(cap_handle);
if use_profile
  T = profile ("info")
  profexplore(T);
end