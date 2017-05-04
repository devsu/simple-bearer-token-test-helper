const Helper = require('./index');
const TestHelper = require('./lib/testHelper');

describe('simple-bearer-token-test-helper', () => {
  it('must expose TestHelper class', () => {
    expect(Helper).toEqual(TestHelper);
  });
});
