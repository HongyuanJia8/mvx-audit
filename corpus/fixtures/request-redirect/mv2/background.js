chrome.webRequest.onBeforeRequest.addListener(
  () => ({ redirectUrl: 'http://127.0.0.1/redirected' }),
  { urls: ['http://127.0.0.1/source'] },
  ['blocking']
);
