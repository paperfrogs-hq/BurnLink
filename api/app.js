const app = require('../app');

// Vercel serverless handler for Express app
module.exports = (req, res) => {
  app(req, res);
};