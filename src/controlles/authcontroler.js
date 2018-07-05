const express = require("express");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

const authConfig = require("../config/auth.json");

const User = require("../models/user");

const router = express.Router();

function generateToken(params = {}) {
  const token = jwt.sign({ params }, authConfig.secret, {
    expiresIn: 86400
  });
  return token;
}

// post
router.post("/register", async (req, res) => {
  const { email } = req.body;

  try {
    // se email já existe retorn erro
    if (await User.findOne({ email }))
      return res.status(400).send({ error: "User already exists" });

    // criando usuario no banco
    const user = await User.create(req.body);

    // retinando o password da resposta
    user.password = undefined;

    return res.send({ user, token: generateToken({ id: user.id }) });
  } catch (err) {
    return res.status(400).send({ error: "Registration failed" });
  }
});

// autenticando usuario
router.post("/authenticate", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select("+password");

  // retornar erro usuario não for encontrado
  if (!user) return res.status(400).send({ error: "User not found" });

  if (!(await bcryptjs.compare(password, user.password)))
    return res.status(400).send({ error: "Invalid password" });

  // retinando o password da resposta
  user.password = undefined;

  res.send({ user, token: generateToken({ id: user.id }) });
});

module.exports = app => app.use("/auth", router);
