import yaml
import utils
import os

def load_config(config_directory):
  global global_config, profiles, transproxies

  global_config = yaml.load(open(os.path.join(config_directory, "global.yaml")).read())

  profiles = []
  for path in utils.list_files(os.path.join(config_directory, "profiles")):
    profiles.append(yaml.load(open(path).read()))

  get_filename = lambda path: os.path.splitext(os.path.basename(path))[0]
  transproxies = {}
  for path in utils.list_files(os.path.join(config_directory, "transproxies")):
    transproxies[get_filename(path)] = (yaml.load(open(path).read()))
