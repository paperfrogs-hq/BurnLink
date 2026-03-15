const app = require('../app');

// Vercel API route handler
module.exports = async (req, res) => {
  app(req, res);
};
