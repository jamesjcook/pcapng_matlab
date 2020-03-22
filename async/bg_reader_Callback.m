function bg_reader_Callback()
  persistent lastupdate = 0;
  global cap;
  global ret;
  % 2 second interval a la -1.
  newtime = floor(time());
  if(newtime > lastupdate)
          % disp('update');
          %fflush(stdout);
          pcapng_read('',ret,cap);
          % pause(0.3);
          lastupdate = newtime;
  end
end
