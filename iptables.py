import os
import utils

class NSIptables:
  def __init__(self):
    self.rules = []
    self.chains = []

  def _call_iptables(self, cmd):
    cmd = "iptables " + cmd
    utils.log("Executing %s" % repr(cmd))
    return os.system(cmd)

  def _iptables_wrapper(self, table, cmd):
    if table:
      cmd = "-t %s %s" % (table, cmd)
    return self._call_iptables(cmd)

  def _add_chain(self, table, chain):
    return self._iptables_wrapper(table, "-N %s" % chain)

  def _del_chain(self, table, chain):
    return self._iptables_wrapper(table, "-X %s" % chain)

  def _add_rule(self, table, chain, rule, rule_num):
    if rule_num > 0:
      return self._iptables_wrapper(table, "-I %s %d %s" % (chain, rule_num, rule))
    else:
      return self._iptables_wrapper(table, "-A %s %s" % (chain, rule))

  def _del_rule(self, table, chain, rule):
    return self._iptables_wrapper(table, "-D %s %s" % (chain, rule))

  def add_chain(self, table, chain):
    self.chains.append((table, chain))
    return self._add_chain(table, chain)

  def del_chain(self, table, chain):
    self.chains.remove((table, chain))
    return self._del_chain(table, chain)

  def add_rule(self, table, chain, rule, rule_num=-1):
    self.rules.append((table, chain, rule))
    return self._add_rule(table, chain, rule, rule_num)

  def del_rule(self, table, chain, rule):
    self.rules.remove((table, chain, rule))
    return self._del_rule(table, chain, rule)
  
  def del_all(self):
    for rule in self.rules[::-1]:
      self._del_rule(*rule)
    for chain in self.chains[::-1]:
      self._del_chain(*chain)

    self.chains = []
    self.rules = []
