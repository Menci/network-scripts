import asyncio
import utils

class NSWatcher:
  def __init__(self):
    # watch_command
    # curr_value
    # process
    # on_change
    raise NotImplementedError()

  async def watch(self):
    self.curr_value = self.get_value(None, None)
    if self.curr_value:
      if asyncio.iscoroutinefunction(self.on_change):
        await self.on_change("", self.curr_value)
      else:
        self.on_change("", self.curr_value)

    async for line_bytes in self.process.stdout:
      line = line_bytes.decode("utf-8")
      utils.log("Read %s" % repr(line))
      new_value = self.get_value(line, self.curr_value)
      if self.curr_value != new_value:
        if asyncio.iscoroutinefunction(self.on_change):
          await self.on_change(self.curr_value, new_value)
        else:
          self.on_change(self.curr_value, new_value)
        self.curr_value = new_value
    utils.log("async for finished, self.process.returncode = %d" % await self.process.wait())

  async def start(self):
    self.process = await asyncio.create_subprocess_shell("setsid %s" % self.watch_command, stdout=asyncio.subprocess.PIPE)
    utils.log("self.process.pid = %d" % self.process.pid);
    asyncio.create_task(self.watch())

  def stop(self):
    try:
      self.process.kill()
    except ProcessLookupError as e:
      utils.log("Error killing process: " + str(e))

  def get_value(self, line):
    raise NotImplementedError()
