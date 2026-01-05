from proc.cli import build_parser
from proc.pipeline import run_mode_list, run_mode_single
from proc.utils import log_err


def main() -> None:
    args = build_parser().parse_args()

    try:
        if args.mode == "list":
            if not args.targets:
                raise SystemExit("[!] Mode 'list' requires --targets.")
            run_mode_list(args)
        else:
            if not args.target:
                raise SystemExit("[!] Mode 'single' requires --target.")
            run_mode_single(args)
    except KeyboardInterrupt:
        raise SystemExit("\n[!] Aborted by user (Ctrl+C).")
    except SystemExit:
        raise
    except Exception as e:
        log_err(f"Unhandled error: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
