function createSyntheticDownload() {
  return chrome.downloads.download({ url: 'data:text/plain,mvx-fixture', saveAs: true });
}
