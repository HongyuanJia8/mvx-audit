async function countAccessibleCookies() {
  return new Promise((resolve) => chrome.cookies.getAll({}, (items) => resolve(items.length)));
}
