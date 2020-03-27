About
-----

Ceph Windows support is currently a work in progress. For now, the main focus
is the client side, allowing Windows hosts to consume rados, rbd and cephfs
resources.

.. _building:
Building
--------

At the moment, mingw gcc is the only supported compiler for building ceph
components for Windows. Support for msvc and clang will be added soon.

`win32_build.sh`_ can be used for cross compiling Ceph and its dependencies.
It may be called from a Linux environment, including Windows Subsystem for
Linux. MSYS2 and CygWin may also work but those weren't tested.

This script currently supports Ubuntu 18.04 and openSUSE Tumbleweed, but it
may be easily adapted to run on other Linux distributions, taking into
account different package managers, package names or paths (e.g. mingw paths).

.. _win32_build.sh: win32_build.sh

The script accepts the following flags:

============  ===============================  ===============================
Flag          Description                      Default value
============  ===============================  ===============================
OS            Host OS distribution, for mingw  ubuntu (also valid: suse)
              and other OS specific settings.
CEPH_DIR      The Ceph source code directory.  The same as the script.
BUILD_DIR     The directory where the          $CEPH_DIR/build
              generated artifacts will be
              placed.
DEPS_DIR      The directory where the Ceph     $CEPH_DIR/build.deps
              dependencies will be built.
NUM_WORKERS   The number of workers to use     The number of vcpus
              when building Ceph.              available
CLEAN_BUILD   Clean the build directory.
SKIP_BUILD    Run cmake without actually
              performing the build.
SKIP_TESTS    Skip building Ceph tests.
BUILD_ZIP     Build a zip archive containing
              the generated binaries.
ZIP_DEST      Where to put a zip containing    $BUILD_DIR/ceph.zip
              the generated binaries.
STRIP_ZIPPED  If set, the zip will contain
              stripped binaries.
============  ===============================  ===============================

In order to build debug binaries as well as an archive containing stripped
binaries that may be easily moved around, one may use the following:

.. code:: bash

    BUILD_ZIP=1 STRIP_ZIPPED=1 SKIP_TESTS=1 ./win32_build.sh

In order to disable a flag, such as ``CLEAN_BUILD``, leave it undefined.

``win32_build.sh`` will fetch dependencies using ``win32_deps_build.sh``. If
all dependencies are successfully prepared, this potentially time consuming
step will be skipped by subsequent builds. Be aware that you may have to do
a clean build (using the ``CLEAN_BUILD`` flag) when the dependencies change
(e.g. after switching to a more recent Ceph version by doing a ``git pull``).

Make sure to explicitly pass the "OS" parameter when directly calling
``win32_deps_build.sh``. Also, be aware of the fact that it will use the distro
specific package manager, which will require privileged rights.

Current status
--------------

The rados and rbd binaries and libs compile successfully and can be used on
Windows, successfully connecting to the cluster and consuming pools.

Ceph filesystems can be mounted using the ``ceph-dokan`` command, which
requires the Dokany package to be installed. Note that dokany is a well
maintained fork of the Dokan project, allowing filesystems to be implemented
in userspace, pretty much like Fuse.

The libraries have to be built statically at the moment. The reason is that
there are a few circular library dependencies or unspecified dependencies,
which isn't supported when building DLLs. This mostly affects ``cls`` libraries.

A significant number of tests from the ``tests`` directory have been ported,
providing adequate coverage.

Installing
----------

Soon we're going to provide an MSI installed for Ceph. For now, unzip the
binaries that you may have obtained by following the building_ step.

You may want to update the environment PATH variable, including the Ceph
path. Assuming that you've copied the Ceph binaries to ``C:\Ceph``, you may
use the following Powershell command:

.. code:: bash

    [Environment]::SetEnvironmentVariable("Path", "$env:PATH;C:\ceph", "Machine")

In order to mount Ceph filesystems, you will have to install Dokany.
You may fetch the installer as well as the source code from the Dokany
Github repository: https://github.com/dokan-dev/dokany/releases

Make sure to use 1.3.1, which at time of the writing is the latest
stable release.

Configuring
-----------

The default location for the ``ceph.conf`` file on Windows is
``%ProgramData%\ceph\ceph.conf``, which usually expands to
``C:\ProgramData\ceph\ceph.conf``. (Note - Directories with spaces
in their names are not currently supported.)

Below you may find a sample. Please fill in the monitor addresses
accordingly.

.. code:: ini

    [global]
        log to stderr = true

        run dir = C:/ProgramData/ceph/out
        crash dir = C:/ProgramData/ceph/out
    [client]
        keyring = C:/ProgramData/ceph/keyring
        ; log file = C:/ProgramData/ceph/out/$name.$pid.log
        admin socket = C:/ProgramData/ceph/out/$name.$pid.asok
    [global]
        mon host =  [v2:xx.xx.xx.xx:40623,v1:xx.xx.xx.xx:40624] [v2:xx.xx.xx.xx:40625,v1:xx.xx.xx.xx:40626] [v2:xx.xx.xx.xx:40627,v1:xx.xx.xx.xx:40628]

Assuming that you're going to use this config sample, don't forget to
also copy your keyring file to the specified location and make sure
that the configured directories exist (e.g. ``C:\ProgramData\ceph\out``).

Please use slashes ``/`` instead of backslashes ``\`` as path separators
within ``ceph.conf`` for the time being.

Usage
-----

Cephfs
======

In order to mount a ceph filesystem, the following command can be used:

.. code:: PowerShell

    ceph-dokan.exe -c c:\ceph.conf -l x

The above command will mount the default ceph filesystem using the drive
letter ``x``. If ``ceph.conf`` is placed at the default location, which
is ``%ProgramData%\ceph\ceph.conf``, then this argument becomes optional.

The ``-l`` argument also allows using an empty folder as a mountpoint
instead of a drive letter.

The uid and gid used for mounting the filesystem defaults to 0 and may be
changed using the ``-u`` and ``-g`` arguments. ``-n`` can be used in order
to skip enforcing permissions on client side. Be aware that Windows ACLs
are ignored. Posix ACLs are supported but cannot be modified using the
current CLI. In the future, we may add some command actions to change
file ownership or permissions.

For debugging purposes, ``-d`` and ``s`` might be used. The first one will
enable debug output and the latter will enable stderr logging. By default,
debug messages are sent to a connected debugger.

You may use ``--help`` to get the full list of available options. The
current syntax is up for discussion and might change.
