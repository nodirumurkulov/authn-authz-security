import type { ZodError } from "zod";
import { ValidationError } from "./authErrors.js";

interface FlatFieldErrors {
  [key: string]: string[];
}

interface FormattedZodError {
  fields: FlatFieldErrors;
  formErrors: string[];
}

/**
 * Convert a ZodError into a user-friendly format and throw a ValidationError.
 * Groups field-level issues under their path and top-level issues separately.
 */
export function throwZodValidationError(error: ZodError, message = "Invalid input"): never {
  const flat = error.flatten();
  const formatted: FormattedZodError = {
    fields: flat.fieldErrors as FlatFieldErrors,
    formErrors: flat.formErrors,
  };
  throw new ValidationError(message, formatted);
}
