


test_bg=0;
profile_me=0;
if ~test_bg && profile_me
  profile off;profile clear;
  profile on;
end
global cap;
global ret;
global bg_reader_timer_id;
global bg_reader;
global bg_analyzer;
global bg_analyzer_timer_id;

% cap_buf test for 1 seconds
ret.s=1;
ret.p=inf;
ret.b=inf;

time_rec=zeros(0);
% Read a second before we launch the bg reader.
t_r=tic;
cap=pcapng_read(cap,ret);
print_limit=8;
time_limit=3*60*60;
history_len=45;
avg_field={'byte_rate','byte_send_rate'};
cap_action='';
local_ip='192.168.1.118';
remote_db_update(cap, print_limit,  time_limit,...
    local_ip,  history_len,  avg_field, cap_action);
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

%{
pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);

pcapng_read('',ret,cap);
remote_db_update();
time_rec(end+1)=toc(t_r);
%}
if numel(time_rec)>2
  fprintf('elapsed=%0.3f\n',time_rec(1));
  for i_t=2:numel(time_rec)
    fprintf('elapsed=%0.3f\n',time_rec(i_t)-time_rec(i_t-1));
  end
end
if ~test_bg
  if profile_me 
    T = profile ("info")
    profexplore(T);
  end
else
% {
bg_reader = figure(1337);
bg_reader_timer_id = add_input_event_hook(@bg_reader_Callback);
set(bg_reader,'CloseRequestFcn',@bg_reader_close)


bg_analyzer= figure(31337);
bg_analyzer_timer_id = add_input_event_hook(@bg_analyzer_Callback);
set(bg_analyzer,'CloseRequestFcn',@bg_analyzer_close)

end
%}