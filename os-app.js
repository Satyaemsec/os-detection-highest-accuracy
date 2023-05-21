const express = require('express');
const { runNmapWorker } = require('./nmap-os.js');

const app = express();
const port = 6000;

app.use(express.json());

app.post('/api/nmap', (req, res) => {
  const { target } = req.body;
  runNmapWorker(target, (err, rest) => {
    if (err) {
      res.status(500).send(err.message);
    } else {
      res.send(rest);
    }
  })
});





app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});


module.exports = {
  app,
 };
