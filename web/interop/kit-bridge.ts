// ortus-kit's call() for the end-to-end peer: each request goes out as a
// line ({"http": …}) and the test answers it from the chat server it runs.
import { next, say } from "./lines.ts";

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  say({ http: { method, path, body: body ?? null } });
  const r = await next();
  if (r.status < 200 || r.status >= 300) throw new ApiError(r.status, JSON.stringify(r.body));
  return r.body as T;
}
