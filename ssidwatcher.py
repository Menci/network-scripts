import utils
import config
from watcher import NSWatcher

class NSSSIDWatcher(NSWatcher):
  def __init__(self, on_change):
    self.watch_command = "ip monitor address"
    self.on_change = on_change

  def get_value(self, line, curr_value):
    if line and not ":" in line:
      utils.log("Skipping %s" % repr(line))
      return curr_value

    out, err = utils.exec(config.global_config["get_ssid_command"])
    
    if err:
      utils.log("SSID: %s" % repr(err));
    
    return out
