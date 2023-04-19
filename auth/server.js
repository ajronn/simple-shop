require("dotenv").config();
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());

const EXPIRY_TIME = 120;
let refreshTokenWhiteList = [];
let accessTokenBlacklist = [];

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: `${EXPIRY_TIME}s`,
  });
}

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;

  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokenWhiteList.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    res.json({ accessToken: generateAccessToken({ name: user.name }) });
  });
});

app.delete("/logout", (req, res) => {
  refreshTokenWhiteList = refreshTokenWhiteList.filter(
    (token) => token !== req.body.token
  );

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    accessTokenBlacklist.push(token);
  });

  res.sendStatus(204);
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username };

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);

  refreshTokenWhiteList.push(refreshToken);
  res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

app.post("/blacklist/verify", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  res.json({
    isCorrect: !accessTokenBlacklist.includes(token),
  });
});

app.listen(4000);
