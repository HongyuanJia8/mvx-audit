chrome.runtime.onMessage.addListener((message) => {
  if (message.openHelp) chrome.tabs.create({ url: 'https://example.invalid/help' });
});
