import 'dart:async';
import 'dart:io';

/// Commit synchronization points intended only for deterministic package tests.
final class FileByteSinkTestHooks {
  const FileByteSinkTestHooks({
    this.afterStagingOwnershipEstablished,
    this.beforeStagingCommit,
    this.beforeStagingCleanup,
    this.beforeNoClobberReservation,
    this.afterNoClobberReservation,
    this.afterNoClobberOwnershipVerified,
    this.duringNoClobberWrite,
  });

  final FutureOr<void> Function(File staging)? afterStagingOwnershipEstablished;
  final FutureOr<void> Function(File staging)? beforeStagingCommit;
  final FutureOr<void> Function(File staging)? beforeStagingCleanup;
  final FutureOr<void> Function(File target)? beforeNoClobberReservation;
  final FutureOr<void> Function(File target)? afterNoClobberReservation;
  final FutureOr<void> Function(File target)? afterNoClobberOwnershipVerified;
  final FutureOr<void> Function(File target)? duringNoClobberWrite;
}
