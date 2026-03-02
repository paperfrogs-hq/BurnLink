require("dotenv").config({ override: true });

const app = require("./app");

if (!process.env.PORT) {
  throw new Error("PORT is missing in .env");
}

const preferredPort = Number(process.env.PORT) || 3000;
const maxPortRetries = Number(process.env.PORT_RETRIES || 10);

function startServer(port, retriesLeft) {
  const server = app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });

  server.on("error", (error) => {
    if (error.code === "EADDRINUSE" && retriesLeft > 0) {
      const nextPort = port + 1;
      console.warn(
        `Port ${port} is busy. Retrying on port ${nextPort} (${retriesLeft} retries left)...`
      );
      startServer(nextPort, retriesLeft - 1);
      return;
    }

    console.error("Failed to start server:", error.message);
    process.exit(1);
  });
}

startServer(preferredPort, maxPortRetries);
