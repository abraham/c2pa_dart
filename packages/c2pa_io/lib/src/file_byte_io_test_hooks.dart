import 'dart:async';
import 'dart:io';

/// Commit synchronization points intended only for deterministic package tests.
final class FileByteSinkTestHooks {
  /// Creates hooks that pause file sink commits at selected checkpoints.
  const FileByteSinkTestHooks({
    this.afterStagingOwnershipEstablished,
    this.beforeStagingCommit,
    this.beforeStagingCleanup,
    this.beforeNoClobberReservation,
    this.afterNoClobberReservation,
    this.afterNoClobberOwnershipVerified,
    this.duringNoClobberWrite,
  });

  /// Callback after the staging file and ownership marker are verified.
  final FutureOr<void> Function(File staging)? afterStagingOwnershipEstablished;

  /// Callback immediately before an overwrite commit renames the staging file.
  final FutureOr<void> Function(File staging)? beforeStagingCommit;

  /// Callback before a failed or aborted commit attempts staging cleanup.
  final FutureOr<void> Function(File staging)? beforeStagingCleanup;

  /// Callback before a no-clobber commit creates the destination reservation.
  final FutureOr<void> Function(File target)? beforeNoClobberReservation;

  /// Callback after a no-clobber destination reservation has been created.
  final FutureOr<void> Function(File target)? afterNoClobberReservation;

  /// Callback after a no-clobber destination ownership marker is verified.
  final FutureOr<void> Function(File target)? afterNoClobberOwnershipVerified;

  /// Callback during the first chunk write of a no-clobber commit.
  final FutureOr<void> Function(File target)? duringNoClobberWrite;
}
