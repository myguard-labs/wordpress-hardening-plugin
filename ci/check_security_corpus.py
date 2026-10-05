"""Reject malformed security corpus YAML before go-ftw selects test files."""

import argparse
from pathlib import Path

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys in every mapping."""

    def construct_mapping(self, node, deep=False):
        # Merge expansion repeats keys when a mapping overrides inherited values.
        # Check only explicit keys, then let SafeLoader apply merge precedence.
        keys = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in keys
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"duplicate mapping key {key!r}",
                    key_node.start_mark,
                )
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def check_corpus(directory):
    """Parse every corpus file, raising on malformed YAML or an empty corpus."""
    paths = sorted(
        path for path in directory.rglob("*") if path.suffix in {".yaml", ".yml"}
    )
    if not paths:
        raise ValueError(f"no YAML corpus files in {directory}")
    for path in paths:
        try:
            with path.open(encoding="utf-8") as stream:
                loader = UniqueKeyLoader(stream)
                try:
                    loader.get_single_data()
                finally:
                    loader.dispose()
        except (yaml.YAMLError, UnicodeError) as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return len(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        count = check_corpus(args.directory)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    suffix = "file" if count == 1 else "files"
    print(f"Validated {count} security corpus YAML {suffix}")


if __name__ == "__main__":
    main()
