"""Windows mapped-reader regression: never truncate a published snapshot."""
import mmap
from pathlib import Path
import sys
import threading

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'standalone'))
from emulate import atomic_snapshot
from work_files import work_directory

def main():
    with work_directory(prefix='vmp-snapshot-test-') as tmp:
        path=Path(tmp)/'snapshot.bin'
        path.write_bytes(b'previous snapshot')
        with path.open('rb') as f:
            mapped=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        try:
            try:
                atomic_snapshot(path,b'new snapshot')
            except OSError:
                assert path.read_bytes()==b'previous snapshot'
            else:
                raise AssertionError('Expected the held Windows mapping to deny replacement')
            assert mapped[:]==b'previous snapshot'
            assert list(path.parent.iterdir())==[path]
            release=threading.Timer(0.25,mapped.close)
            release.start()
            try:
                atomic_snapshot(path,b'new snapshot')
            finally:
                release.join()
            assert path.read_bytes()==b'new snapshot'
            assert list(path.parent.iterdir())==[path]
        finally:
            mapped.close()
    print('PASS: mapped reader preserves the old snapshot; transient locks retry; no partial files remain')

if __name__=='__main__': main()
