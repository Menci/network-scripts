import config
from iptables import NSIptables

class NSTransproxy:
  def __init__(self, route, local_routes, extra_routes):
    self.route = route
    self.local_routes = local_routes
    self.extra_routes = extra_routes
    self.iptables = NSIptables()

  async def exec_start(self):
    raise NotImplementedError()

  async def start(self):
    fwmark = config.global_config["transproxy"]["fwmark"]

    self.iptables.add_chain("mangle", "TRANSPROXY_MARK")

    # Mark packets to extra_routes
    for extra_cidr in self.extra_routes or []:
      self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-d %s -j MARK --set-mark %d" % (extra_cidr, fwmark))

    # Skip private CIDRs that isn't in extra_routes
    self.iptables.add_rule("mangle", "TRANSPROXY_MARK",
                           "-m set --match-set network-scripts-private-cidr dst -j RETURN")

    # Skip non-private local CIDRs
    for local_cidr in (self.local_routes or []) + (config.global_config["transproxy"]["local_routes"] or []):
      self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-d %s -j RETURN" % local_cidr)

    # bypass-mainland-china: Mark all packets to non-Mainland China CIDRs
    # only-mainland-china: Mark all packets to Mainland China CIDRs
    # all: Mark all non-RETURNed packets
    if self.route == "bypass-mainland-china":
      self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-m set ! --match-set network-scripts-mainland-china dst -j MARK --set-mark %d" % fwmark)
    elif self.route == "only-mainland-china":
      self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-m set --match-set network-scripts-mainland-china dst -j MARK --set-mark %d" % fwmark)
    elif self.route == "all":
      self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-j MARK --set-mark %d" % fwmark)

    await self.exec_start()
  
  def exec_stop(self):
    raise NotImplementedError()

  def stop(self):
    self.exec_stop()
    self.iptables.del_all()
