const serverless = require("serverless-http");
process.env.BURNLINK_BUFFERED_FUNCTION = "true";
const app = require("../../app");

module.exports.handler = serverless(app);
