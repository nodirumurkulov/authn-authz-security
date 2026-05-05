import { loadConfig } from "./config.js";
import { buildApp } from "./app.js";

const config = loadConfig();
const app = await buildApp(config);

const address = await app.listen({ port: config.PORT, host: "0.0.0.0" });
app.log.info(`Listening on ${address}`);
