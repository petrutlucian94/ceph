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
