import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('C2paSettings', () {
    test('uses conservative defaults', () {
      const settings = C2paSettings();

      expect(settings.allowNetworkAccess, isFalse);
      expect(settings.enableOcspFetch, isFalse);
      expect(settings.maxOcspRequestBytes, 16 * 1024);
      expect(settings.maxOcspResponseBytes, 1024 * 1024);
      expect(settings.ocspMaxAgeWithoutNextUpdate, const Duration(hours: 24));
      expect(settings.ocspClockSkew, const Duration(minutes: 5));
      expect(settings.maxResourceBytes, 50 * 1024 * 1024);
      expect(settings.maxTotalResourceBytes, 200 * 1024 * 1024);
      expect(settings.maxRecursionDepth, 16);
      expect(settings.maxManifestBytes, 64 * 1024 * 1024);
      expect(settings.maxJumbfBoxCount, 10000);
      expect(settings.networkTimeout, const Duration(seconds: 10));
    });

    test('round-trips JSON and supports value equality', () {
      final settings = const C2paSettings().copyWith(
        allowNetworkAccess: true,
        maxRedirects: 1,
        networkTimeout: const Duration(milliseconds: 250),
      );

      final decoded = C2paSettings.fromJson(settings.toJson());

      expect(decoded, settings);
      expect(decoded.hashCode, settings.hashCode);
    });
  });
}
