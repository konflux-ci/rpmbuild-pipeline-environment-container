#!/usr/bin/python3
import argparse
import os
import sys

from koji.rpmdiff import Rpmdiff


def get_params():
    parser = argparse.ArgumentParser()
    parser.add_argument('--results-dir', default='/var/workdir/results',
                        help="Path to results directory")
    args = parser.parse_args()
    return args


args = get_params()

noarch_files = {}

errors = 0
for root, _, files in os.walk(args.results_dir):
    for fname in files:
        if fname.endswith('.noarch.rpm'):
            fpath = os.path.join(root, fname)
            hash = Rpmdiff(fpath, fpath, ignore='S5TN').kojihash()
            if fname in noarch_files:
                if hash != noarch_files[fname]:
                    errors += 1
                    print(f'{fname} mismatch')
            else:
                noarch_files[fname] = hash
if errors:
    print(f"{errors} errors found")
    sys.exit(1)
else:
    print("All noarch rpms matches each other.")
