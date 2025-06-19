"""
Asteroid Web Application Security Scanner
This script is designed to dynamically load and run various web application security scanning modules
from a specified folder. It allows users to specify which modules to run, skip, or list, and handles
previous runs of the modules.
@author: Harm-r
"""

import argparse
import importlib
import os
from urllib.parse import urlparse
import shlex
import sys
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm
import time

from modules.constants import OUTPUT_DIR, DEFAULT_RATE_LIMIT
from modules.logger_config import set_logger
from modules.utils import logger


def load_modules(modules_folder):
    """Dynamically loads all modules in the specified folder and its subfolders."""
    modules = []
    for root, _, files in os.walk(modules_folder):  # Recursively traverse directories
        # Limit traversal to the modules folder and one subdirectory below it
        if os.path.relpath(root, modules_folder).count(os.sep) >= 1:
            continue

        for filename in files:
            if filename.endswith(".py") and not filename.startswith("__"):
                relative_path = os.path.relpath(root, os.path.dirname(modules_folder))
                package_path = ".".join(relative_path.split(os.sep))
                module_name = filename[:-3]  # Remove .py extension
                full_module_name = (
                    f"{package_path}.{module_name}"
                    if package_path
                    else f"{module_name}"
                )

                try:
                    # Import the module as part of the package
                    module = importlib.import_module(full_module_name)
                    modules.append(module)
                except Exception as e:
                    logger.error(f"Error loading module {full_module_name}: {e}")
    return modules


def load_module_instances(modules, args):
    """Loads and sorts module instances."""
    instances = []
    for module in modules:
        for attr_name in dir(module):
            if attr_name.endswith(
                "Module"
            ):  # Dynamically find classes ending with "Module"
                module_class = getattr(module, attr_name)
                if (
                    callable(module_class) and module_class.__name__ != "BaseModule"
                ):  # Ensure it's a class
                    instances.append(module_class(args))
    return sorted(instances, key=lambda x: x.index)


def select_modules(instances, args):
    if args.list_modules:
        logger.info("Available modules:")
        for instance in instances:
            logger.info(f"{instance.index}: {instance.name} - {instance.description}")
        sys.exit(0)

    if args.modules:
        if args.modules.lower() == "all":
            return instances
        selected = args.modules.lower().split(",")
        return [instance for instance in instances if instance.name.lower() in selected]

    if args.skip_modules:
        skipped = args.skip_modules.lower().split(",")
        return [
            instance
            for instance in instances
            if instance.name.lower() not in skipped and instance.is_default_module
        ]

    return [instance for instance in instances if instance.is_default_module]


def check_rerun(args, modules_to_run):
    # Check if any module has been run before
    if args.rerun:
        return 0  # Start from the first module

    for index, instance in enumerate(modules_to_run[::-1]):
        if instance.has_run_before():
            if args.cont:
                return len(modules_to_run) - index

            logger.warning(
                f"{instance.name} module has already run. Do you want to rerun it? ([Y]es/[n]o/[a]ll)",
                extra={"output_to_file": False},
            )
            answer = input().strip().lower()
            if answer.startswith("n"):
                return len(modules_to_run) - index
            if answer.startswith("a"):
                return 0
    return 0


def check_target_rerun(args, list_of_targets, output_dir=OUTPUT_DIR):
    # Check if any target has been scanned before
    if args.rerun:
        return 0  # Start from the first target

    for index, target in enumerate(list_of_targets[::-1]):
        target_name = urlparse(target).netloc
        if os.path.exists(os.path.join(output_dir, target_name)):
            if args.cont:
                return len(list_of_targets) - index

            logger.warning(
                f"Scan of {target_name} has already run. Do you want to rerun it? ([Y]es/[n]o/[a]ll)",
                extra={"output_to_file": False},
            )
            answer = input().strip().lower()
            if answer.startswith("n"):
                return len(list_of_targets) - index
            if answer.startswith("a"):
                return 0
    return 0


def asteroid():
    # Create the main argument parser
    parser = argparse.ArgumentParser(
        prog="asteroid",
        description="Runs all Asteroid Web Application Security Scanner modules.",
    )
    parser.add_argument(
        "target",
        help="The target domain to crawl, or a file containing domains",
        nargs="?",
    )
    parser.add_argument("-o", "--output", help="Output directory to save results")
    parser.add_argument("--modules", help="Comma-separated list of modules to run")
    parser.add_argument(
        "--skip-modules", help="Comma-separated list of modules to skip"
    )
    parser.add_argument(
        "--list-modules", help="List all modules and exit", action="store_true"
    )
    parser.add_argument(
        "--rerun", help="Rerun even if previous output is detected", action="store_true"
    )
    parser.add_argument(
        "--continue",
        help="Continue from the last module run",
        action="store_true",
        dest="cont",
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose output", action="store_true"
    )
    parser.add_argument(
        "-rl",
        "--rate-limit",
        help="Maximum requests to send per second",
        default=DEFAULT_RATE_LIMIT,
    )

    arguments_without_help = (
        " ".join(sys.argv[1:]).replace("-h", "").replace("--help", "")
    )
    arguments_without_help = shlex.split(arguments_without_help)
    general_args, _ = parser.parse_known_args(
        arguments_without_help
    )  # Create a temporary parser to get default values

    set_logger(logger)

    list_of_targets = []
    if not general_args.target:
        logger.critical("Please provide a target")
        sys.exit(1)
    elif os.path.isfile(general_args.target):
        with open(general_args.target, "r") as f:
            list_of_targets = [line.strip() for line in f if line.strip()]
    else:
        list_of_targets = [general_args.target]

    # Load all modules and allow them to add their arguments
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    modules = load_modules(modules_folder)
    for module in modules:
        if hasattr(module, "add_arguments"):
            module.add_arguments(parser)

    # Parse the arguments with the added module arguments
    args = parser.parse_args()
    for general_arg in vars(general_args):
        if getattr(args, general_arg) is None:
            setattr(args, general_arg, getattr(general_args, general_arg))

    output_dir = OUTPUT_DIR
    if args.output:
        output_dir = args.output

    starting_target_index = check_target_rerun(args, list_of_targets, output_dir)

    with logging_redirect_tqdm():
        for target in tqdm(
            list_of_targets[starting_target_index:],
            desc="Targets",
            unit="target",
            colour="green",
        ):
            args.target = target

            target_name = urlparse(args.target).netloc
            if target_name:
                args.output = os.path.join(output_dir, target_name)
            else:
                args.output = output_dir

            if args.verbose:
                set_logger(logger, outputdir=args.output, level="DEBUG")
            else:
                set_logger(logger, outputdir=args.output)

            logger.info(f"[SCANNING TARGET: {target}]")

            # Load each module
            instances = load_module_instances(modules, args)

            # Process the modules and skip-modules arguments
            modules_to_run = select_modules(instances, args)

            # Check if we should rerun any modules
            starting_index = check_rerun(args, modules_to_run)

            logger.info(
                "[%s - Starting scan]",
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            )
            for instance in tqdm(
                modules_to_run[starting_index:],
                desc="Modules",
                unit="module",
                colour="green",
            ):
                try:
                    logger.info(f"[{instance.index} - {instance.name}]")
                    if not instance.pre():
                        logger.warning(
                            f"Skipping {instance.name} module due to precondition failure."
                        )
                    else:
                        instance.run()
                        instance.post()
                except KeyboardInterrupt:
                    logger.warning(
                        "Keyboard interrupt detected. Exiting.",
                        extra={"output_to_file": False},
                    )
                    sys.exit(0)
                except Exception as e:
                    logger.error(f"Error running {instance.name} module: {e}")


if __name__ == "__main__":
    asteroid()
