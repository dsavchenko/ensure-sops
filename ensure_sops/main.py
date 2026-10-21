import os
import pathlib
import re
import sys
from argparse import ArgumentParser
from typing import Dict, List, Optional, Tuple, Any

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
    argparser.add_argument("--sops-yaml-path", type=str, default=".sops.yaml")
    argparser.add_argument("--verify-keys", action="store_true")
    return argparser

def _verify_keys(
    values: Dict[str, Any]
) -> Optional[str]:

    allowed_keys = {
        "Secret": {
            "apiVersion",
            "data",
            "immutable",
            "kind",
            "metadata",
            "stringData",
            "type",
            "sops"
        },

        "Configmap": {
            "apiVersion",
            "binaryData",
            "data",
            "immutable",
            "kind",
            "metadata",
            "sops"
        },
    }

    kind = values.get("kind", None)
    if kind is None:
        return "Not a kubernetes resource. Please turn off --verify-keys."
    if kind not in allowed_keys:
        return f"{kind} keys verification is not supported. Please turn off --verify-keys."
    key_set = allowed_keys.get(kind)
    extra_keys = set(values.keys()) - key_set
    if extra_keys:
        return f"verify-keys: Keys not allowed in {kind}: {extra_keys}"
    
    return None


def _validate_files(
    paths: List[pathlib.Path],
    method: Methods,
    verify_keys: bool,
    creation_rules: Optional[List[Tuple[re.Pattern, re.Pattern]]] = None,
) -> Dict[pathlib.Path, str]:
    failed_files = {}

    for path in paths:
        with path.open() as stream:
            validator = SopsValidator(stream, path.name, method=method)
            fmt, values = validator.parse()

            if verify_keys:
                res = _verify_keys(values)
                if res: 
                    failed_files[path] = res
                    continue

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

def _read_creation_rules(yaml_path):
    creation_rules = None

    try:
        if os.path.isfile(yaml_path):
            with open(yaml_path) as fd:
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
        creation_rules = _read_creation_rules(yaml_path=parsed_args.sops_yaml_path)
    else:
        creation_rules = None

    errors = _validate_files(parsed_args.files, parsed_args.method, verify_keys=parsed_args.verify_keys, creation_rules=creation_rules)

    if errors:
        for path, error in errors.items():
            print(f"{path} - {error}", file=sys.stderr)
        return 1
    return 0
