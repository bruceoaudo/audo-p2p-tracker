import express from "express";
import client from "prom-client";

const app = express();
const register = new client.Registry();

client.collectDefaultMetrics({ register });

app.get("/metrics", async (req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

app.listen(8000, () => console.log("Metrics exposed on port 8000"));
