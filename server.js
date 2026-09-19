// Entry point Render actually runs. Loads the app from
// analystiq-backend-FULL.js and starts it listening on the port Render
// assigns (via process.env.PORT) — Render sets this automatically, you
// don't need to configure it.
const app = require('./analystiq-backend-FULL.js');

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`AnalystIQ backend running on port ${PORT}`);
});
