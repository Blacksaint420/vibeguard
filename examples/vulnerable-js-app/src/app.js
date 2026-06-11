import express from "express";

const app = express();

app.post("/run", (req, res) => {
  eval(req.body.code);
  res.send("ok");
});

app.get("/user", async (req, res) => {
  const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;
  res.json({ sql });
});

export default app;
