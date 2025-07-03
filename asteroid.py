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


class Asteroid:
    def __init__(
        self,
        target,
        output_dir=OUTPUT_DIR,
        specific_modules="default",
        skip_modules=None,
        list_modules=False,
        rerun=False,
        cont=False,
        verbose=False,
        rate_limit=DEFAULT_RATE_LIMIT,
        module_args={},
    ):
        """
        Initializes the Asteroid scanner with the general arguments and loads modules.
        """
        list_of_targets = []
        if not target:
            logger.critical("Please provide a target")
            sys.exit(1)
        elif os.path.isfile(target):
            with open(target, "r") as f:
                list_of_targets = [line.strip() for line in f if line.strip()]
        else:
            list_of_targets = [target]

        self.target = list_of_targets

        self.output_dir = output_dir
        self.specific_modules = specific_modules
        self.skip_modules = skip_modules
        self.list_modules = list_modules
        self.rerun = rerun
        self.cont = cont
        self.verbose = verbose
        self.rate_limit = rate_limit

        # Other arguments are copied to modules_args in _load_module_instances
        self.modules_args = module_args

        # Load modules from the specified folder
        modules_folder = os.path.join(os.path.dirname(__file__), "modules")
        self.modules = self._load_modules(modules_folder)

    def _load_modules(self, modules_folder):
        """Dynamically loads all modules in the specified folder and its subfolders."""
        modules = []
        for root, _, files in os.walk(
            modules_folder
        ):  # Recursively traverse directories
            # Limit traversal to the modules folder and one subdirectory below it
            if os.path.relpath(root, modules_folder).count(os.sep) >= 1:
                continue

            for filename in files:
                if filename.endswith(".py") and not filename.startswith("__"):
                    relative_path = os.path.relpath(
                        root, os.path.dirname(modules_folder)
                    )
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

    def _load_module_instances(self, modules):
        """Loads and sorts module instances."""

        # Copy all attributes from the instance to modules_args
        for arg, value in vars(self).items():
            if arg not in self.modules_args and arg != "modules_args":
                self.modules_args[arg] = value

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
                        instances.append(module_class(self.modules_args))
        return sorted(instances, key=lambda x: x.index)

    def _select_modules(self, instances):
        if self.list_modules:
            logger.info("Available modules:")
            for instance in instances:
                logger.info(
                    f"{instance.index}: {instance.name} - {instance.description}"
                )
            sys.exit(0)

        if self.specific_modules:
            if self.specific_modules.lower() == "all":
                return instances
            selected = self.specific_modules.lower().split(",")
            return [
                instance for instance in instances if instance.name.lower() in selected
            ]

        if self.skip_modules:
            skipped = self.skip_modules.lower().split(",")
            return [
                instance
                for instance in instances
                if instance.name.lower() not in skipped and instance.is_default_module
            ]

        return [instance for instance in instances if instance.is_default_module]

    def _check_rerun(self, modules_to_run):
        # Check if any module has been run before
        if self.rerun:
            return 0  # Start from the first module

        for index, instance in enumerate(modules_to_run[::-1]):
            if instance.has_run_before():
                if self.cont:
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

    def _check_target_rerun(self):
        # Check if any target has been scanned before
        if self.rerun:
            return 0  # Start from the first target

        for index, target in enumerate(self.target[::-1]):
            target_name = urlparse(target).netloc
            if os.path.exists(os.path.join(self.output_dir, target_name)):
                if self.cont:
                    return len(self.target) - index

                logger.warning(
                    f"Scan of {target_name} has already run. Do you want to rerun it? ([Y]es/[n]o/[a]ll)",
                    extra={"output_to_file": False},
                )
                answer = input().strip().lower()
                if answer.startswith("n"):
                    return len(self.target) - index
                if answer.startswith("a"):
                    return 0
        return 0

    def parse_module_args(self, parser):
        """
        Parses module-specific arguments from the command line.
        """
        for module in self.modules:
            if hasattr(module, "add_arguments"):
                module.add_arguments(parser)

        # Parse the arguments with the added module arguments
        parsed_args = vars(parser.parse_args())
        # Do not overwrite module arguments that are already set
        for arg, value in parsed_args.items():
            if arg not in self.modules_args:
                self.modules_args[arg] = value

    def run(self):
        set_logger(logger)

        starting_target_index = self._check_target_rerun()

        with logging_redirect_tqdm():
            for single_target in tqdm(
                self.target[starting_target_index:],
                desc="Targets",
                unit="target",
                colour="green",
            ):
                target_name = urlparse(single_target).netloc
                if target_name:
                    self.output_dir = os.path.join(self.output_dir, target_name)

                if self.verbose:
                    set_logger(logger, outputdir=self.output_dir, level="DEBUG")
                else:
                    set_logger(logger, outputdir=self.output_dir)

                logger.info(f"[SCANNING TARGET: {single_target}]")

                # Load each module
                self.modules_args["target"] = single_target
                instances = self._load_module_instances(self.modules)

                # Process the modules and skip-modules arguments
                modules_to_run = self._select_modules(instances)

                # Check if we should rerun any modules
                starting_index = self._check_rerun(modules_to_run)

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


def setup_argparse():
    """Sets up the argument parser for the Asteroid scanner."""
    parser = argparse.ArgumentParser(
        prog="asteroid",
        description="Runs all Asteroid Web Application Security Scanner modules.",
    )
    parser.add_argument(
        "target",
        help="The target domain to crawl, or a file containing domains",
        nargs="?",
    )
    parser.add_argument(
        "-o", "--output", help="Output directory to save results", default=OUTPUT_DIR
    )
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
    return parser


if __name__ == "__main__":
    parser = setup_argparse()

    # Parse general arguments without help option
    arguments_without_help = (
        " ".join(sys.argv[1:]).replace("-h", "").replace("--help", "")
    )
    arguments_without_help = shlex.split(arguments_without_help)
    general_args, _ = parser.parse_known_args(arguments_without_help)

    asteroid = Asteroid(
        target=general_args.target,
        output_dir=general_args.output,
        specific_modules=general_args.modules,
        skip_modules=general_args.skip_modules,
        list_modules=general_args.list_modules,
        rerun=general_args.rerun,
        cont=general_args.cont,
        verbose=general_args.verbose,
        rate_limit=general_args.rate_limit,
    )

    asteroid.parse_module_args(parser)

    asteroid.run()
