import re
import click

# Convert opcodes to the ACT expected format
desired_names = {
  "StatusEffectList": None,
  "StatusEffectList2": None,
  "StatusEffectList3": None,
  "BossStatusEffectList": None,
  "Effect": "Ability1",
  "AoeEffect8": "Ability8",
  "AoeEffect16": "Ability16",
  "AoeEffect24": "Ability24",
  "AoeEffect32": "Ability32",
  "ActorCast": None,
  "EffectResult": None,
  "EffectResultBasic": None,
  "ActorControl": None,
  "ActorControlSelf": None,
  "ActorControlTarget": None,
  "UpdateHpMpTp": None,
  "PlayerSpawn": None,
  "NpcSpawn": None,
  "NpcSpawn2": None,
  "ActorMove": None,
  "ActorSetPos": None,
  "ActorGauge": None,
  "PlaceFieldMarkerPreset": "PresetWaymark",
  "PlaceFieldMarker": "Waymark",
  "SystemLogMessage": None
}

@click.command()
@click.argument("opcodes_file", type=click.File('r'))
def generate_act_format(opcodes_file):
  opcode_mapping = dict()

  for line in opcodes_file.readlines():
    match_groups = re.findall(r'^\s*([^\/].*)= (.*),\s*\/\/.*$', line)
    if len(match_groups) != 1:
      continue

    opcode_name = match_groups[0][0].strip()
    opcode_val = match_groups[0][1]
    if " or " in opcode_val:
      opcodes = [int(v, 16) for v in opcode_val.split(" or ")]
    else:
      opcodes = [int(opcode_val, 16)]
    opcode_mapping[opcode_name] = opcodes

  for name, desired in desired_names.items():
    if desired == None:
      desired = name
    opcodes = opcode_mapping[name]
    if len(opcodes) == 1:
      print(f'{desired}|{opcodes[0]:x}')
    elif len(opcodes) > 1:
      print(f'{desired}|{[f"{opcode:x}" for opcode in opcodes]}')

if __name__ == "__main__":
  generate_act_format()