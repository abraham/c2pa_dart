import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

void main() {
  test('loads JSON values and typed object goldens on the VM', () async {
    final value = await loadGoldenJson('test/goldens/oracle.json');
    final object = await loadGoldenJsonObject('test/goldens/oracle.json');

    expect(value, object);
    expect(object['state'], 'valid');
    expect(object['issues'], isEmpty);
  });

  test('typed loader rejects non-object JSON', () {
    expect(
      loadGoldenJsonObject('test/goldens/array.json'),
      throwsFormatException,
    );
  });
}
