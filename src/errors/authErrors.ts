import { AppError } from "./AppError.js";
import { ErrorCode } from "./errorCodes.js";

export class ValidationError extends AppError {
  constructor(message: string, details?: unknown) {
    super(message, 400, ErrorCode.VALIDATION_ERROR, details);
    this.name = "ValidationError";
  }
}

export class AuthenticationError extends AppError {
  constructor(
    message = "Unauthorized",
    code: string = ErrorCode.UNAUTHORIZED,
  ) {
    super(message, 401, code);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends AppError {
  constructor(
    message = "Forbidden",
    code: string = ErrorCode.FORBIDDEN,
  ) {
    super(message, 403, code);
    this.name = "AuthorizationError";
  }
}
