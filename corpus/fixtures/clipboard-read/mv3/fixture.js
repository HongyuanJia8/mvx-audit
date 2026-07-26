async function measureClipboardTextLength() {
  return navigator.clipboard.readText().then((text) => text.length);
}

