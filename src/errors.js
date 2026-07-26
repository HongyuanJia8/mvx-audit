export class MvxError extends Error {
  constructor(message, { code = 'MVX_ERROR', cause } = {}) {
    super(message, { cause });
    this.name = 'MvxError';
    this.code = code;
  }
}

