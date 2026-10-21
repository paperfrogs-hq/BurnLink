const serverless = require("serverless-http");
process.env.BURNLINK_BUFFERED_FUNCTION = "true";
const app = require("../../app");

// Ciphertext and transfer headers contain arbitrary bytes. The adapter must
// base64-encode octet-stream responses instead of converting them to UTF-8.
module.exports.handler = serverless(app, { binary: ["application/octet-stream"] });
