export class AgentSafeFSError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = 'AgentSafeFSError';
    this.code = code;
    this.details = details;
  }
}

export function fail(code, message, details = null) {
  throw new AgentSafeFSError(code, message, details);
}
