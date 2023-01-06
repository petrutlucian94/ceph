$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop"

python.exe ./test_rbd_wnbd.py --test-name RbdTest --iterations 100
python.exe ./test_rbd_wnbd.py --test-name RbdFioTest --iterations 100
python.exe ./test_rbd_wnbd.py --test-name RbdStampTest --iterations 100

# It can take a while to setup the partition (~10s), we'll use fewer iterations.
python.exe ./test_rbd_wnbd.py --test-name RbdFsTest --iterations 4
python.exe ./test_rbd_wnbd.py --test-name RbdFsFioTest --iterations 4
python.exe ./test_rbd_wnbd.py --test-name RbdFsStampTest --iterations 4

python.exe ./test_rbd_wnbd.py --test-name RbdResizeFioTest --image-size-mb 64
