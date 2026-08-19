#!/usr/bin/env python3

import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkstemp
from typing import IO, Iterator

# What a conversion writes holds the content of the MISP events or STIX
# documents it converted - TLP:AMBER and TLP:RED material, attachments
# included: an output file is readable by the user who produced it and by
# nobody else, whatever the process umask would have allowed
_OUTPUT_FILE_MODE = 0o600


class _Output:
    """The scratch file a conversion writes, before it becomes the output.

    `write` takes the content in as many steps as the conversion needs;
    `discard` says the conversion ended up with nothing worth keeping, so the
    destination is left as it was.
    """

    def __init__(self, stream: IO):
        self._stream = stream
        self._discarded = False

    @property
    def discarded(self) -> bool:
        return self._discarded

    def discard(self):
        self._discarded = True

    def write(self, content: bytes | str) -> int:
        return self._stream.write(content)


@contextmanager
def _open_output(
        destination: Path | str, *, overwrite: bool = False,
        binary: bool = False) -> Iterator[_Output]:
    """Write the destination in one step, or not at all.

    Content goes to a scratch file in the destination's own directory - a
    replace is atomic within a single filesystem only - and reaches the
    destination once all of it is there. A conversion interrupted halfway
    through therefore leaves what was there untouched, rather than a
    truncated file where the operator's previous export used to be, and a
    destination that already exists is only written when the caller asked
    for it.
    """
    destination = Path(destination)
    if destination.exists() and not overwrite:
        raise FileExistsError(_exists_message(destination))
    handle, scratch_name = mkstemp(
        dir=destination.parent, prefix=f'.{destination.name}.', suffix='.part'
    )
    scratch = Path(scratch_name)
    try:
        os.chmod(scratch, _OUTPUT_FILE_MODE)
        with open(
                handle, 'wb' if binary else 'wt',
                encoding=None if binary else 'utf-8') as stream:
            output = _Output(stream)
            yield output
            stream.flush()
            os.fsync(stream.fileno())
        if output.discarded:
            scratch.unlink(missing_ok=True)
        else:
            _commit(scratch, destination, overwrite)
    except BaseException:
        # However it ended - an exception from the conversion, a signal
        # killing the process - the scratch file holds converted content and
        # the destination has not been touched: only the scratch file goes
        scratch.unlink(missing_ok=True)
        raise


def _write_output(
        destination: Path | str, content: bytes | str,
        overwrite: bool = False):
    with _open_output(
            destination, overwrite=overwrite,
            binary=isinstance(content, bytes)) as output:
        output.write(content)


def _commit(scratch: Path, destination: Path, overwrite: bool):
    # Asked to overwrite, the scratch file replaces whatever is there.
    # Otherwise the destination has to be *created*: a link fails where a
    # replace would silently clobber a file that appeared while the
    # conversion ran, which the check taken before the work cannot see. A
    # filesystem carrying no links falls back to the replace, and to that
    # check as its only guard
    if overwrite:
        os.replace(scratch, destination)
        return
    try:
        os.link(scratch, destination)
    except FileExistsError:
        raise FileExistsError(_exists_message(destination))
    except OSError:
        os.replace(scratch, destination)
        return
    scratch.unlink(missing_ok=True)


def _exists_message(destination: Path) -> str:
    return (
        f'{destination} already exists - pass `overwrite=True` '
        '(`--overwrite` on the command line) to replace it.'
    )


def _private_opener(path: str, flags: int) -> int:
    # The `opener` a plain `open` call takes to create its file owner-only,
    # for the content a conversion writes outside the funnel above - the
    # scratch fragments of a streamed assembly
    return os.open(path, flags, _OUTPUT_FILE_MODE)
