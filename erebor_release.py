#!/usr/bin/env python

import argparse
from subprocess import check_output

from git import Repo
import semantic_version


def get_version_from_git():
    """
    Retrieves version number from latest tag and parses.

    return: git_version: UTF-8 parsed string in 'x.y.z' format, string
    """
    label = check_output(
        ['git', 'describe', '--tags']
    )
    git_version_string = label.strip().decode('UTF-8')
    git_version = semantic_version.Version(git_version_string)
    git_version = '.'.join(str(item) for item in list(git_version)[:3])
    return git_version if semantic_version.validate(git_version) else False


def branch_checker():
    """
    Retrieves current branch to ensure developer is on master.

    return: branch: UTF-8 parsed string of the branch name, string
    """
    label = check_output(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD']
    )
    branch = label.strip().decode('UTF-8')
    return branch == 'master'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-mi', '--minor', action='store_true')
    parser.add_argument('-ma', '--major', action='store_true')
    parser.add_argument('-p', '--patch', action='store_true')
    args = vars(parser.parse_args())
    if not branch_checker():
        raise Exception("Checkout branch 'master' before proceeding.")
    git_version = get_version_from_git()
    git_version = semantic_version.Version(git_version)

    increment = {k: args[k] for k in args if args[k] is True}

    # No version arguments supplied. Defaulting to "minor" 0.x.0
    if not len(increment):
        increment_type = 'minor'
        new_version = git_version.next_minor()

    # One version argument supplied. Either "major": x.0.0, "minor": 0.x.0,
    # or "patch": 0.0.x
    elif len(increment) == 1:
        increment_type = list(increment.keys())[0]
        new_version = getattr(git_version, 'next_' + increment_type)()

    # Multiple version arguments supplied. Unsupported
    else:
        raise Exception("Multiple version arguments detected." +
                        " Please supply one or none to default to minor")

    repo = Repo()
    git = repo.git
    git.tag(new_version, '-a', '-m', 'applied {}'.format(increment_type))
    git.push('origin', new_version)
