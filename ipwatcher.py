import utils
from watcher import NSWatcher

class NSIPWatcher(NSWatcher):
  def __init__(self, interface, on_change):
    self.interface = interface
    self.watch_command = "ip monitor address dev %s" % interface
    self.on_change = on_change

  def get_value(self, line, curr_value):
    if line and not self.interface in line:
      utils.log("Skipping %s" % repr(line))
      return curr_value

    out, err = utils.exec("ip -4 address show %s | awk -F '[ /]*' '/inet/ { print $3 }'" % self.interface)
    
    if err:
      utils.log("ip address: %s" % repr(err));
    
    return out
