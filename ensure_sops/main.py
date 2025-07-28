import os
import pathlib
import re
import sys
from argparse import ArgumentParser
from typing import Dict, List, Optional, Tuple

from ruamel.yaml import YAML

from .exceptions import ValidationError
from .validator import Methods, SopsValidator

yaml = YAML(typ="safe")


def _get_parser() -> ArgumentParser:
    argparser = ArgumentParser()
    argparser.add_argument("files", type=pathlib.Path, nargs="+")
    argparser.add_argument(
        "--method", type=Methods, choices=list(Methods), default=Methods.strict
    )
    argparser.add_argument("--use-sops-yaml", action="store_true")
    return argparser


def _validate_files(
    paths: List[pathlib.Path],
    method: Methods,
    creation_rules: Optional[List[Tuple[re.Pattern, re.Pattern]]] = None,
) -> Dict[pathlib.Path, str]:
    failed_files = {}

    for path in paths:
        with path.open() as stream:
            validator = SopsValidator(stream, path.name, method=method)
            fmt, values = validator.parse()
            encrypted_regex = None
            if creation_rules is not None:
                for rule in creation_rules:
                    if rule[0].match(str(path)):
                        encrypted_regex = rule[1]
                        break
            try:
                validator.check_encryption(fmt, values, encrypted_regex)
            except ValidationError as e:
                failed_files[path] = str(e)
    return failed_files


def _read_creation_rules():
    creation_rules = None

    try:
        if os.path.isfile(".sops.yaml"):
            with open(".sops.yaml") as fd:
                values = yaml.load(fd)
                creation_rules = values.get("creation_rules", None)

        if creation_rules is not None:
            creation_rules = [
                (
                    re.compile(item["path_regex"]),
                    re.compile(item["encrypted_regex"]),
                )
                for item in creation_rules
            ]

    except Exception as e:
        print(f"Unable to load creation_rules from .sops.yaml: {e}")

    return creation_rules


def main(args: Optional[List[str]] = None) -> int:
    parser = _get_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.use_sops_yaml:
        creation_rules = _read_creation_rules()
    else:
        creation_rules = None

    errors = _validate_files(parsed_args.files, parsed_args.method, creation_rules)

    if errors:
        for path, error in errors.items():
            print(f"{path} - {error}", file=sys.stderr)
        return 1
    return 0
