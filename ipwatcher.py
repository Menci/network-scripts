import utils
from watcher import NSWatcher

class NSIPWatcher(NSWatcher):
  def __init__(self, interface, ignored_ip_address, on_change):
    self.interface = interface
    self.watch_command = "ip monitor address dev %s" % interface
    self.on_change = on_change
    self.ignored_ip_address = ignored_ip_address if type(ignored_ip_address) == list else [ignored_ip_address]

  def get_value(self, line, curr_value):
    if line:
      found = False
      for ip in self.ignored_ip_address:
        if " %s/" % ip in line:
          found = True
          break
      if found or self.interface not in line:
        utils.log("Skipping %s" % repr(line))
        return curr_value

    out, err = utils.exec("ip -4 address show %s | awk -F '[ /]*' '/inet/ { print $3 }'" % self.interface)

    if err:
      utils.log("ip address: %s" % repr(err));

    ips = out.split('\n')
    for ip in ips:
      if ip in self.ignored_ip_address:
        return ip
    
    return ""
