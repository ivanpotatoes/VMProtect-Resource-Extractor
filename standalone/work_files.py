"""Windows temporary work directories with inherited user-directory ACLs."""
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile
import uuid

@contextmanager
def work_directory(prefix='vmp-',root=None):
    parent=Path(root or tempfile.gettempdir()).resolve()
    path=parent/(prefix+uuid.uuid4().hex)
    # Python 3.14's mode-0700 Windows ACL is incompatible with restricted tokens.
    # The user's TEMP directory supplies the access policy instead.
    path.mkdir(mode=0o777)
    try:
        yield str(path)
    finally:
        if path.parent.resolve()!=parent: raise RuntimeError('Unexpected temporary directory parent')
        shutil.rmtree(path)
