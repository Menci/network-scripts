import utils
import config
from iptables import NSIptables
from ipwatcher import NSIPWatcher

class NSNat:
  def __init__(self, wan_interfaces, dmz_host):
    self.wan_interfaces = wan_interfaces
    self.dmz_host = dmz_host
    self.watchers = []
    self.iptables = NSIptables()

  def _on_ip_change(self, old_ip, new_ip):
    utils.log((old_ip, new_ip))
    if old_ip:
      self.iptables.del_rule("nat", "PREROUTING", "-d %s -m socket --nowildcard -j ACCEPT" % old_ip)
      self.iptables.del_rule("nat", "PREROUTING", "-d %s -j DNAT --to-destination %s" % (old_ip, self.dmz_host))
    if new_ip:
      self.iptables.add_rule("nat", "PREROUTING", "-d %s -m socket --nowildcard -j ACCEPT" % new_ip)
      self.iptables.add_rule("nat", "PREROUTING", "-d %s -j DNAT --to-destination %s" % (new_ip, self.dmz_host))

  async def start(self):
    utils.log()

    self.iptables.add_rule("nat", "POSTROUTING", "-s %s -j MASQUERADE" % config.global_config["dmz_host"])
    self.iptables.add_rule("mangle", "POSTROUTING", "-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")

    for wan_interface in self.wan_interfaces:
      watcher = NSIPWatcher(wan_interface, self._on_ip_change)
      await watcher.start()
      self.watchers.append(watcher)
  
  def stop(self):
    utils.log()
    for watcher in self.watchers:
      watcher.stop()
    self.iptables.del_all()
