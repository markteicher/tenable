def load_config(args):
    return {
        "access_key": args.access_key,
        "secret_key": args.secret_key,
        "proxy": args.proxy,
        "verbose": args.verbose
    }
