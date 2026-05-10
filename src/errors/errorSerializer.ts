import { AppError } from "./AppError.js";
import { ErrorCode } from "./errorCodes.js";

export interface StructuredErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
    requestId?: string;
  };
}

export function serializeError(
  err: unknown,
  requestId?: string,
): { statusCode: number; body: StructuredErrorResponse } {
  if (err instanceof AppError) {
    return {
      statusCode: err.statusCode,
      body: {
        error: {
          code: err.code,
          message: err.message,
          ...(err.details !== undefined ? { details: err.details } : {}),
          ...(requestId ? { requestId } : {}),
        },
      },
    };
  }

  return {
    statusCode: 500,
    body: {
      error: {
        code: ErrorCode.INTERNAL_ERROR,
        message: "Internal server error",
        ...(requestId ? { requestId } : {}),
      },
    },
  };
}
