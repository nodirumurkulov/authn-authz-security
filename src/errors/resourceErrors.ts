import { AppError } from "./AppError.js";
import { ErrorCode } from "./errorCodes.js";

export class NotFoundError extends AppError {
  constructor(resource = "Resource") {
    super(`${resource} not found`, 404, ErrorCode.NOT_FOUND);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends AppError {
  constructor(message = "Conflict", code: string = ErrorCode.CONFLICT) {
    super(message, 409, code);
    this.name = "ConflictError";
  }
}

export class RateLimitError extends AppError {
  constructor(message = "Too many attempts") {
    super(message, 429, ErrorCode.RATE_LIMITED);
    this.name = "RateLimitError";
  }
}

export class AccountLockedError extends AppError {
  constructor() {
    super("Account is locked", 423, ErrorCode.ACCOUNT_LOCKED);
    this.name = "AccountLockedError";
  }
}

export class ServerMisconfigurationError extends AppError {
  constructor(message = "Server misconfiguration") {
    super(message, 500, ErrorCode.SERVER_MISCONFIGURATION);
    this.name = "ServerMisconfigurationError";
  }
}
