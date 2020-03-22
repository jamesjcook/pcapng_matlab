function bg_analyzer_close(src,evnt)
  global bg_analyzer;
  global bg_analyzer_timer_id;
  remove_input_event_hook(bg_analyzer_timer_id);
  disp('Closing figure... Bye!');
  fflush(stdout);
  delete(bg_analyzer);
end
