/** An error returned by the Airport HTTP API. */
export class AirportApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "AirportApiError";
    this.status = status;
    this.code = code;
  }
}

/** A frame-level error delivered over the socket. */
export class AirportSocketError extends Error {
  readonly code: string;
  readonly msgId?: string;
  readonly fatal: boolean;

  constructor(code: string, message: string, msgId?: string, fatal = false) {
    super(message);
    this.name = "AirportSocketError";
    this.code = code;
    this.msgId = msgId;
    this.fatal = fatal;
  }
}
