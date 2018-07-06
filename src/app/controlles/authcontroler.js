const express = require("express");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const mailer = require("../../modules/mailer");

const authConfig = require("../../config/auth.json");

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

router.post("/forgot_password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) return res.status(401).send({ error: "User not founded" });

    const token = crypto.randomBytes(20).toString("hex");
    const now = new Date();
    now.setHours(now.getHours() + 1);

    console.log(user.id);

    await User.findByIdAndUpdate(user.id, {
      $set: {
        passwordResetToken: token,
        passwordResetExpires: now
      }
    });

    mailer.sendMail(
      {
        to: "d31a78192a-45f4a6@inbox.mailtrap.io",
        from: "d31a78192a-45f4a6@inbox.mailtrap.io",
        template: "auth/forgot_password",
        context: { token }
      },
      err => {
        if (err) {
          return res
            .status(400)
            .send({ error: "Cannot send forgot password email" });
        }
        return res.send({ ok: true });
      }
    );
    return res.status(200).send({ ok: "foi bem" });
  } catch (err) {
    console.log(err);
    res.status(400).send({ error: "Error on forgot password, try again" });
  }
});

router.post("/reset_password", async (req, res) => {
  const { email, token, password } = req.body;
  try {
    const user = await User.findOne({ email }).select(
      "+passwordResetToken passwordResetExpires"
    );

    if (!user) return res.status(400).send({ error: "User not found" });

    if (token !== user.passwordResetToken) {
      console.log(token + "///" + user.passwordResetToken + " +++ " + user);
      return res.status(400).send({ error: "Invalid Token" });
    }
    const now = new Date();

    if (now > user.passwordResetExpires)
      return res
        .status(400)
        .send({ error: "Token expired, generate a new one" });

    user.password = password;

    await user.save();

    res.send();
  } catch (error) {
    res.status(400).send({ error: "Cannot reset password, try again" });
  }
});
module.exports = app => app.use("/auth", router);
