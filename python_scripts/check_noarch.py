#!/usr/bin/python3
import argparse
import os
import subprocess
import sys


def get_params():
    """Parse command line args"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--results-dir', default='/var/workdir/results',
                        help="Path to results directory")
    args = parser.parse_args()
    return args


def _main():
    params = get_params()
    noarch_files = {}

    for root, _, files in os.walk(params.results_dir):
        for fname in files:
            if fname.endswith('.noarch.rpm'):
                fpath = os.path.join(root, fname)
                noarch_files.setdefault(fname, []).append(fpath)

    errors = 0
    print(f'Comparing {len(noarch_files.keys())} file(s)')
    for fpaths in noarch_files.values():
        if len(fpaths) < 2:
            continue
        baseline = fpaths[0]
        for fpath in fpaths[1:]:
            print(f'Comparing {baseline} vs. {fpath}', end='\t')
            sys.stdout.flush()
            results = subprocess.run(
                ["rpmdiff", "-i", "S", "5", "T", "N", "--", baseline, fpath],
                capture_output=True,
                check=False
            )
            if results.returncode:
                print('mismatch')
                print(results.stdout.decode())
                errors += 1
            else:
                print('match')

    if errors:
        print(f"{errors} errors found")
        sys.exit(1)
    else:
        print("All noarch rpms matches each other.")

if __name__ == "__main__":
    _main()
