function bg_analyzer_Callback()
  persistent lastupdate = 0;
  global bg_analyzer;
  persistent empty_reads=0;
  max_empty=20;
  % for 2 second interval adjust by -1.
  % for < 0.5 second interval adjust by +0.5 (a fraction <1)
  newtime = floor(time())+0.5;
  if(newtime > lastupdate)
          % disp('update');
          %fflush(stdout);
% DO WORK HERE.
          p_c=remote_db_update();
          if p_c==0
            empty_reads=empty_reads+1;
          end
          if empty_reads>=max_empty
            warning('shutting down analyzer');
            close(bg_analyzer);
          end
          % pause(0.3);
          lastupdate = newtime;
  end
end
