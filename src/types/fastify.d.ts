export type SessionUser = {
  id: string;
  email: string;
  createdAt: Date;
  roles: { name: string }[];
};

declare module "fastify" {
  interface FastifyRequest {
    sessionUser: SessionUser | null;
  }
}
