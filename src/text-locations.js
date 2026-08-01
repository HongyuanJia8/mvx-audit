export function lineStarts(content) {
  const starts = [0];
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index];
    if (character === '\r') {
      if (content[index + 1] === '\n') index += 1;
      starts.push(index + 1);
    } else if (character === '\n' || character === '\u2028' || character === '\u2029') {
      starts.push(index + 1);
    }
  }
  return starts;
}

export function lineAt(starts, offset) {
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = Math.floor((low + high) / 2);
    if (starts[middle] <= offset) low = middle;
    else high = middle;
  }
  return low + 1;
}

export function lineSnippet(content, starts, line, maximum = 240) {
  const start = starts[line - 1] ?? 0;
  let end = start;
  while (end < content.length && end - start < maximum) {
    const character = content[end];
    if (character === '\r' || character === '\n'
      || character === '\u2028' || character === '\u2029') break;
    end += 1;
  }
  return content.slice(start, end).trim().slice(0, maximum);
}
