const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
    res.json({ message: "API Dockerisée fonctionnelle!", status: 200 });
});

app.listen(port, () => {
    console.log(`API en écoute sur le port ${port}`);
});
