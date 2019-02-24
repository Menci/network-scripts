import re
import utils
import config
from ssidwatcher import NSSSIDWatcher

from transproxy.shadowsocks import NSShadowsocksTransproxy
from transproxy.wireguard import NSWireGuardTransproxy

class NSAutoSwitcher:
  def __init__(self, profiles):
    self.profiles = profiles
    self.watcher = None
    self.curr_profile = None
    self.transproxy = None

  def _match_profile(self, ssid):
    for profile in self.profiles:
      if re.match(profile["match_ssid"], ssid):
        return profile
    raise Exception("No profile matches SSID %s, missing default profile" % repr(ssid))

  def _get_transproxy(self, transproxy_config, local_routes):
    transproxy_config = config.transproxies[transproxy_config]

    TransproxyType = None
    if transproxy_config["type"] == "shadowsocks":
      TransproxyType = NSShadowsocksTransproxy
    elif transproxy_config["type"] == "wireguard":
      TransproxyType = NSWireGuardTransproxy
    else:
      raise NotImplementedError()

    return TransproxyType(transproxy_config["route"],
                          local_routes,
                          transproxy_config["extra_routes"],
                          transproxy_config["config"])

  async def _switch_profile(self, new_profile):
    if self.curr_profile and new_profile and self.curr_profile["transproxy"] == new_profile["transproxy"]:
      utils.log((self.curr_profile["name"], new_profile["name"]), "Same transproxy rule, not switching")
      return

    if self.curr_profile and self.transproxy:
      utils.log((self.curr_profile["name"], new_profile["name"]), "Stopping old profile's transproxy")
      self.transproxy.stop()
      self.transproxy = None

    if new_profile and new_profile["transproxy"] and new_profile["transproxy"]["config"]:
      self.transproxy = self._get_transproxy(new_profile["transproxy"]["config"],
                                             new_profile["transproxy"]["local_routes"])
      await self.transproxy.start()

  async def _on_ssid_change(self, old_ssid, new_ssid):
    utils.log((old_ssid, new_ssid))
    new_profile = self._match_profile(new_ssid)
    
    if new_profile == self.curr_profile:
      utils.log((old_ssid, new_ssid), "Old SSID and new SSID matches same profile: %s" % repr(new_profile["name"]))
      return

    await self._switch_profile(new_profile)
    self.curr_profile = new_profile

  async def start(self):
    utils.log()
    self.watcher = NSSSIDWatcher(self._on_ssid_change)
    await self.watcher.start()

  def stop(self):
    utils.log()
    self.watcher.stop()
    if self.transproxy:
      self.transproxy.stop()

