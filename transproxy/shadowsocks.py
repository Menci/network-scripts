import os
import grp
import asyncio
import utils
import config
from transproxy.transproxy import NSTransproxy
from iptables import NSIptables

class NSShadowsocksTransproxy(NSTransproxy):
  def __init__(self, route, local_routes, extra_ruotes, config):
    super().__init__(route, local_routes, extra_ruotes)
    self.config = config
    self.iptables = NSIptables()
    self.stopped = False
  
  async def _run_ss_redir(self):
    utils.log()

    run_group = config.global_config["transproxy"]["shadowsocks"]["run_group"]
    run_gid = run_group if type(run_group) == int else grp.getgrnam(run_group).gr_gid
    local_port = config.global_config["transproxy"]["shadowsocks"]["local_port"]
    server = self.config["server"]
    server_port = self.config["port"]
    password = self.config["password"]
    method = self.config["method"]

    ss_redir_command = "ss-redir -s %s -k %s -p %d -b 0.0.0.0 -l %d -m %s -u --no-delay" \
                       % (repr(server), repr(password), server_port, local_port, repr(method))

    while True:
      self.process = await asyncio.create_subprocess_shell(ss_redir_command,
                                                           stdout=asyncio.subprocess.PIPE,
                                                           stderr=asyncio.subprocess.STDOUT,
                                                           preexec_fn=lambda: (os.setgid(run_gid), os.setsid()))
      utils.log("self.process.pid = %d" % self.process.pid)
      async for line in self.process.stdout:
        utils.log("ss-redir: %s" % line.decode("utf-8").strip())
      utils.log("ss-redir exited with %d" % await self.process.wait())

      if self.stopped:
        break

      await asyncio.sleep(config.global_config["transproxy"]["shadowsocks"]["restart_interval"])

      if self.stopped:
        break
    
    utils.log("Stopped")

  async def exec_start(self):
    fwmark = config.global_config["transproxy"]["fwmark"]
    ip_route_table = config.global_config["transproxy"]["ip_route_table"]
    run_group = config.global_config["transproxy"]["shadowsocks"]["run_group"]
    local_port = config.global_config["transproxy"]["shadowsocks"]["local_port"]

    # TCP
    self.iptables.add_rule("nat", "PREROUTING", "-p tcp -m mark --mark %d -j REDIRECT --to-ports %d" % (fwmark, local_port))
    self.iptables.add_rule("nat", "OUTPUT", "-p tcp -m mark --mark %d -j REDIRECT --to-ports %d" % (fwmark, local_port))

    # UDP
    self.iptables.add_rule("mangle", "PREROUTING", "-p udp -m mark --mark %d -j TPROXY --on-port %d --tproxy-mark %d/%d"
                                                   % (fwmark, local_port, fwmark, fwmark))
    utils.system("ip route add local default dev lo table %s" % ip_route_table)
    utils.system("ip rule add fwmark %s lookup %s" % (fwmark, ip_route_table))

    asyncio.create_task(self._run_ss_redir())

    # Active the rules
    self.iptables.add_rule("mangle", "OUTPUT", "-m owner ! --gid-owner %s -j TRANSPROXY_MARK" % run_group)
    self.iptables.add_rule("mangle", "PREROUTING", "-j TRANSPROXY_MARK", 1)

  def exec_stop(self):
    fwmark = config.global_config["transproxy"]["fwmark"]
    ip_route_table = config.global_config["transproxy"]["ip_route_table"]

    self.iptables.del_all()
    utils.system("ip route del local default dev lo table %s" % ip_route_table)
    utils.system("ip rule del fwmark %s lookup %s" % (fwmark, ip_route_table))

    self.stopped = True

    if type(self.process.returncode) != int:
      utils.log("Killing ss-redir process")
      self.process.kill()
    else:
      utils.log("Not killing ss-redir process, since self.process.returncode is int")
