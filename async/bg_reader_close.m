function bg_reader_close(src,evnt)
  global bg_reader;
  global bg_reader_timer_id;
  remove_input_event_hook(bg_reader_timer_id);
  disp('Closing figure... Bye!');
  fflush(stdout);
  delete(bg_reader);
end
