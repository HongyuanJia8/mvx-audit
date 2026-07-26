async function countAccessibleCookies() {
  return chrome.cookies.getAll({}).then((items) => items.length);
}

