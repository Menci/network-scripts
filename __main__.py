import asyncio
import signal
import os
import argparse
import utils
import config
from nat import NSNat
from autoswitcher import NSAutoSwitcher
from iptables import NSIptables

class NSMain:
  def __init__(self):
    self.nat = NSNat(config.global_config["ignored_ip_address"], config.global_config["wan_interfaces"])
    self.auto_switcher = NSAutoSwitcher(config.profiles)
    self.iptables = NSIptables()
    self.signaled = False

  async def start(self):
    await self.nat.start()
    await self.auto_switcher.start()

    for custom_iptables_rule in config.global_config["custom_iptables_rules"]:
      self.iptables.add_rule(custom_iptables_rule.get("table"),
                             custom_iptables_rule.get("chain"),
                             custom_iptables_rule.get("rule"),
                             custom_iptables_rule.get("rule_num") or -1)
  
  def stop(self):
    if self.signaled:
      utils.log("Duplicate signals, ignoring")
      return

    utils.log("Signaled, stopping")

    self.signaled = True

    self.iptables.del_all()

    self.auto_switcher.stop()
    self.nat.stop()

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--config", help="configure files directory", required=True)
arguments = parser.parse_args()

config.load_config(arguments.config)

main = NSMain()

loop = asyncio.get_event_loop()

loop.add_signal_handler(signal.SIGINT, main.stop)
loop.add_signal_handler(signal.SIGTERM, main.stop)

loop.run_until_complete(main.start())
loop.run_until_complete(asyncio.gather(*asyncio.Task.all_tasks()))

