import asyncio
import socket
import utils
import config
from transproxy.transproxy import NSTransproxy
from iptables import NSIptables

class NSWireGuardTransproxy(NSTransproxy):
  def __init__(self, route, local_routes, extra_ruotes, config):
    super().__init__(route, local_routes, extra_ruotes)
    self.config = config
    self.iptables = NSIptables()
    self.stopped = False
    self.started = False
  
  async def _try_run(self):
    utils.log()

    endpoint_host = self.config["endpoint_host"]
    endpoint_port = self.config["endpoint_port"]
    local_address = self.config["local_address"]
    private_key = self.config["private_key"]
    remote_public_key = self.config["remote_public_key"]
    fwmark = config.global_config["transproxy"]["fwmark"]
    ip_route_table = config.global_config["transproxy"]["ip_route_table"]
    interface_name = config.global_config["transproxy"]["wireguard"]["interface_name"]
    resolve_retry_interval = config.global_config["transproxy"]["wireguard"]["resolve_retry_interval"]

    endpoint_ip = None
    while not endpoint_ip:
      try:
        endpoint_ip = socket.gethostbyname(endpoint_host)
      except BaseException as e:
        utils.log("Failed to resolve %s: %s" % (endpoint_host, e))

      if self.stopped:
        break

      await asyncio.sleep(resolve_retry_interval)
    
    if self.stopped:
      utils.log("Cancelled before add WireGuard interface.")
      return

    if endpoint_ip != endpoint_host:
      utils.log("Resolved endpoint host %s to %s" % (endpoint_host, endpoint_ip))

    # Start WireGuard
    utils.system("ip link add dev %s type wireguard" % interface_name)
    utils.system("ip address add dev %s %s" % (interface_name, local_address))
    utils.system("wg set %s private-key <(echo %s) peer %s allowed-ips 0.0.0.0/0 endpoint %s:%d"
                 % (interface_name, repr(private_key), repr(remote_public_key), endpoint_ip, endpoint_port))
    utils.system("ip link set up dev %s" % interface_name)

    # Set ip route and ip rule
    utils.system("ip route add table %d default dev %s" % (ip_route_table, interface_name))
    utils.system("ip rule add fwmark %d table %d" % (fwmark, ip_route_table))

    self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-d %s -p udp --dport %d -j RETURN" % (endpoint_ip, endpoint_port), 1)
    self.iptables.add_rule("mangle", "TRANSPROXY_MARK", "-i wireguard -j RETURN", 1)
    self.iptables.add_rule("nat", "POSTROUTING", "-o wireguard -j MASQUERADE")
    self.iptables.add_rule("mangle", "OUTPUT", "-j TRANSPROXY_MARK")
    self.iptables.add_rule("mangle", "PREROUTING", "-j TRANSPROXY_MARK")

    self.started = True

  async def exec_start(self):
    asyncio.create_task(self._try_run())

  def exec_stop(self):
    self.stopped = True

    if self.started:
      fwmark = config.global_config["transproxy"]["fwmark"]
      ip_route_table = config.global_config["transproxy"]["ip_route_table"]
      interface_name = config.global_config["transproxy"]["wireguard"]["interface_name"]

      self.iptables.del_all()

      utils.system("ip route del table %d default dev %s" % (ip_route_table, interface_name))
      utils.system("ip rule del fwmark %d table %d" % (fwmark, ip_route_table))

      utils.system("ip link delete %s" % interface_name)
