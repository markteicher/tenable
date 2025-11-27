import argparse
from pytenable_was.commands import scans, assets, plugins, templates
from pytenable_was.utils.logging import configure_logging
from pytenable_was.config import load_config

def main():
    parser = argparse.ArgumentParser(
        description="pytenable-was: Tenable WAS CLI Tool"
    )

    # Global arguments
    parser.add_argument('--access-key', required=True, help="Tenable API Access Key")
    parser.add_argument('--secret-key', required=True, help="Tenable API Secret Key")
    parser.add_argument('--proxy', help="Optional proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging")

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', required=True)

    scans.register(subparsers)
    assets.register(subparsers)
    plugins.register(subparsers)
    templates.register(subparsers)

    args = parser.parse_args()

    # Configure logging
    configure_logging(verbose=args.verbose)

    # Load config
    config = load_config(args)

    # Dispatch to appropriate module
    if args.command == "scans":
        scans.run(args, config)
    elif args.command == "assets":
        assets.run(args, config)
    elif args.command == "plugins":
        plugins.run(args, config)
    elif args.command == "templates":
        templates.run(args, config)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
