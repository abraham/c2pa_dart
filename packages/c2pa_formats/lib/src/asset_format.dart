/// An asset container format supported by the C2PA format layer.
enum AssetFormat {
  /// Standalone C2PA store, MIME `application/c2pa`, extension `.c2pa`.
  standaloneC2pa,

  /// JPEG image, MIME `image/jpeg` or `image/jpg`, extension `.jpg`.
  jpeg,

  /// PNG image, MIME `image/png`, extension `.png`.
  png,

  /// GIF image, MIME `image/gif`, extension `.gif`.
  gif,

  /// WebP RIFF image, MIME `image/webp` or `image/x-webp`, extension `.webp`.
  webp,

  /// WAVE RIFF audio, MIME `audio/wav` or `audio/wave`, extension `.wav`.
  wav,

  /// AVI RIFF video, MIME `video/avi` or `video/x-msvideo`, extension `.avi`.
  avi,

  /// TIFF or DNG image, MIME `image/tiff` or `image/dng`, extension `.tif`.
  tiff,

  /// MP3 audio, MIME `audio/mpeg` or `audio/mp3`, extension `.mp3`.
  mp3,

  /// FLAC audio, MIME `audio/flac`, extension `.flac`.
  flac,

  /// SVG image, MIME `image/svg+xml`, extension `.svg`.
  svg,

  /// MP4 ISO BMFF video, MIME `video/mp4`, extension `.mp4`.
  mp4,

  /// QuickTime movie, MIME `video/quicktime`, extension `.mov`.
  mov,

  /// MPEG-4 audio, MIME `audio/mp4` or `audio/x-m4a`, extension `.m4a`.
  m4a,

  /// AVIF image, MIME `image/avif`, extension `.avif`.
  avif,

  /// HEIF image, MIME `image/heif`, extension `.heif`.
  heif,

  /// HEIC image, MIME `image/heic`, extension `.heic`.
  heic,

  /// JPEG XL image, MIME `image/jxl`, extension `.jxl`.
  jpegXl,

  /// Generic ZIP archive, MIME `application/zip`, extension `.zip`.
  zip,

  /// EPUB publication, MIME `application/epub+zip`, extension `.epub`.
  epub,

  /// Office Open XML package.
  ///
  /// MIME types are the Word, Excel, and PowerPoint OOXML types; typical
  /// extensions are `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm`.
  ooxml,

  /// OpenDocument package.
  ///
  /// MIME types are the ODT, ODS, ODP, and ODG media types; typical
  /// extensions are `.odt`, `.ods`, `.odp`, `.odg`, `.ott`, `.ots`, `.otp`.
  openDocument,

  /// OpenXPS package, MIME `application/oxps`, extension `.oxps`.
  openXps,

  /// PDF document, MIME `application/pdf`, extension `.pdf`.
  pdf,

  /// Asset format that could not be detected by configured handlers.
  unknown,
}

/// The evidence used to select an [AssetFormat] during detection.
///
/// [mimeType] is strongest caller metadata, [fileExtension] is a normalized
/// suffix, [magicBytes] is handler probing, and [none] means no match.
enum AssetDetectionMethod {
  /// Detection by a caller-provided MIME type.
  mimeType,

  /// Detection by a caller-provided file extension.
  fileExtension,

  /// Detection by probing the asset's leading bytes.
  magicBytes,

  /// No detection evidence because no handler matched.
  none,
}
