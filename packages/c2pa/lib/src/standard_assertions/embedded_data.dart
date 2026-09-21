part of '../standard_assertions.dart';

/// Opaque binary assertion data with an explicit label and MIME type.
class C2paEmbeddedData implements C2paStandardAssertion {
  /// Creates an embedded binary assertion.
  ///
  /// Throws FormatException when the label or content type is empty.
  C2paEmbeddedData({
    required this.label,
    required this.contentType,
    required Iterable<int> bytes,
  }) : bytes = Uint8List.fromList(bytes.toList()).asUnmodifiableView() {
    if (label.isEmpty || contentType == null || contentType!.isEmpty) {
      throw const FormatException(
        'Embedded data requires a label and content type',
      );
    }
  }
  @override
  final String label;
  @override
  final String? contentType;

  /// Immutable assertion bytes copied from the constructor input.
  final Uint8List bytes;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.binary;
  @override
  Uint8List toAssertionData() => Uint8List.fromList(bytes);
  @override
  bool operator ==(Object other) =>
      other is C2paEmbeddedData &&
      label == other.label &&
      contentType == other.contentType &&
      deepEquals(bytes, other.bytes);
  @override
  int get hashCode => Object.hash(label, contentType, deepHash(bytes));
}

/// Thumbnail assertion target represented by a C2PA thumbnail label.
enum C2paThumbnailKind {
  /// Thumbnail for the claim asset.
  claim,

  /// Thumbnail for an ingredient asset.
  ingredient,
}

/// Embedded thumbnail assertion for a claim or ingredient.
final class C2paThumbnail extends C2paEmbeddedData {
  /// Creates a thumbnail and derives its C2PA label from the media type.
  ///
  /// Throws FormatException for unsupported thumbnail media types.
  C2paThumbnail({
    required this.kind,
    required String mediaType,
    required super.bytes,
  }) : super(label: _thumbnailLabel(kind, mediaType), contentType: mediaType);

  /// Interprets embedded data whose label uses a C2PA thumbnail prefix.
  factory C2paThumbnail.fromEmbedded(C2paEmbeddedData data) {
    final kind = data.label.startsWith('c2pa.thumbnail.ingredient')
        ? C2paThumbnailKind.ingredient
        : C2paThumbnailKind.claim;
    return C2paThumbnail._(
      kind: kind,
      label: data.label,
      mediaType: data.contentType!,
      bytes: data.bytes,
    );
  }
  C2paThumbnail._({
    required this.kind,
    required super.label,
    required String mediaType,
    required super.bytes,
  }) : super(contentType: mediaType);

  /// Thumbnail target represented by the derived label.
  final C2paThumbnailKind kind;
}
