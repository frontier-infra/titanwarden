"""Offline broker release checks. Does not open a broker, socket or live store."""
import subprocess
import sys


def main():
    commands = [
        ['uv', 'sync', '--frozen'],
        ['uv', 'run', 'python', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
        ['uv', 'run', 'python', '-O', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
        ['uv', 'run', 'python', '-m', 'compileall', '-q', 'tw'],
        ['git', 'diff', '--check', 'origin/main...HEAD'],
        ['git', 'diff', '--check'],
    ]
    for command in commands:
        print('Running:', ' '.join(command), flush=True)
        result = subprocess.run(command)
        if result.returncode:
            return result.returncode
    patch = subprocess.check_output(['git', 'diff', '--unified=0', 'origin/main...HEAD'], text=True)
    additions = [line for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++')]
    if any('\u2013' in line or '\u2014' in line for line in additions):
        print('Added text contains a forbidden dash character', file=sys.stderr)
        return 1
    print('Offline gate passed.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
