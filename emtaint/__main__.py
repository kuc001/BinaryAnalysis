"""Run the BinaryAnalysis command-line interface as a Python module."""

if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'acquire':
        from .acquire_cli import main

        raise SystemExit(main(sys.argv[2:]))
    from .cli import main

    raise SystemExit(main())
