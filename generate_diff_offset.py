import click
import json


@click.command()
@click.argument("diff_file", type=click.File("r"))
@click.argument("offset", type=int)
def generate_diff_offset(diff_file, offset):
    """
    Given a diff file, produces another diff file where the matches
    are offset by OFFSET.

    Example:
    python generate_diff_offset.py -- diff.json -1 > offset.diff.json
    """
    diff_json = json.load(diff_file)
    olds = []
    news = []
    for pair in diff_json:
        if "old" not in pair or "new" not in pair:
            continue
        olds.append(pair["old"])
        news.append(pair["new"])

    if offset < 0:
        news = [[] for _ in range(-offset)] + news
    if offset > 0:
        olds = [[] for _ in range(offset)] + olds

    opcodes_object = []
    for old, new in zip(olds, news):
        opcodes_object.append(
            {
                "old": old,
                "new": new,
            }
        )

    print(json.dumps(opcodes_object, indent=2))


if __name__ == "__main__":
    generate_diff_offset()
