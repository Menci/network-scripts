import sys
import subprocess
import os
import inspect
import datetime
import time
import termcolor

def log(arguments=[], text=None):
  if type(arguments) == str:
    text = arguments
    arguments = []

  def get_class_name(obj):
    return None if obj is None else obj.__class__.__name__

  frame = inspect.stack()[1][0]
  now = datetime.datetime.now()
  time_str = "%s.%03d" % (time.strftime("%b %d %H:%M:%S", now.timetuple()), now.microsecond / 1000)
  time_str = termcolor.colored(time_str, "magenta")

  caller_name = None
  class_name = get_class_name(frame.f_locals.get("self"))
  func_name = termcolor.colored(frame.f_code.co_name, "green")
  if class_name:
    caller_name = "[%s] %s" % (class_name, func_name)
  else:
    module_name = inspect.getmodule(frame).__name__
    if module_name == "__main__":
      module_name = "main"
    caller_name = "%s.%s" % (module_name, func_name)

  prefix = "%s %s(%s)" % (time_str, caller_name, ("%s, " * len(arguments))[:-2]) \
                       % tuple(termcolor.colored(repr(s), "yellow") for s in arguments)

  if text:
    print("%s: %s" % (prefix, text), file=sys.stderr)
  else:
    print(prefix, file=sys.stderr)

  sys.stderr.flush()

def system(command):
  log("Executing %s" % repr(command))
  out, err = exec(command)

  if err:
    for line in err.split("\n"):
      log("stderr: %s" % line)

  return out

def exec(command, trim=True):
  process = subprocess.Popen(
    ["/bin/bash", "-c", command],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
  )
  out, err = process.communicate()

  out = out.decode("utf-8")
  err = err.decode("utf-8")

  if trim:
    out = out.strip()
    err = err.strip()

  return out, err

def list_files(directory):
  paths = [os.path.join(directory, filename) for filename in os.listdir(directory)
                                             if os.path.isfile(os.path.join(directory, filename))]
  paths.sort()
  return paths
