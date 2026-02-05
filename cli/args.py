import argparse

def handle_binary(args):
    print(f"Binary type: {args.exec}")
    print(f"File: {args.file}")

def parsing_arg():
    parser = argparse.ArgumentParser(description="DesOfuscaXOR")

    parser.add_argument("file", help="Path to the binary to analyze")

    parser.add_argument(
        "-e", "--exec",
        choices=["elf32", "elf64", "pe32", "pe64"],
        required=True,
        help="Specify the binary type and architecture"
    )

    parser.set_defaults(func=handle_binary)
    args = parser.parse_args()
    args.func(args)

    return args.exec, args.file