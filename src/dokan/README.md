About
-----

Ceph filesystems can be mounted using the ``ceph-dokan`` command, which
requires the Dokany package to be installed. Note that dokany is a well
maintained fork of the Dokan project, allowing filesystems to be implemented
in userspace, pretty much like Fuse.

Error handling
--------------

Dokan expects NTSTATUS return values, so we must avoid returning negative
error codes.

Wherever possible, we should convert libceph errors to NTSTATUS values,
returning a generic STATUS_INTERNAL_ERROR otherwise.

Permissions
-----------
Cephfs only supports Posix ACLs, so Windows ACLs will be discarded.

``ceph-dokan`` accepts uid/gid values (defaulting to 0) that will be used
when mounting filesystems and creating files. Unless configured otherwise,
the Posix ACLs will be checked against the configured credentials.

File locking
------------
Cephfs doesn't support mandatory file locks, which Windows is heavily rely
upon. At the moment, we're letting Dokan handle file locks, which are
only enforced locally.

Logging
-------
At the moment, the logging conforms to Dokan's logging style. DbgPrint(W)
is used for debug messages, which are printed by connected debuggers (if
any). If configured to do so, those errors can be printed to stderr. This
option will also propagate to the Dokan lib.

In the future, we might consider switching to Ceph's logging mechanism.
We should also avoid using different log calls for what should be part of
the same message. Dokany uses multiple threads, for which reason
messages from different operations can get mixed up.
