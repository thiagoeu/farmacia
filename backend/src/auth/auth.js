import express from "express";
import passport from "passport";
import LocalStrategy from "passport-local";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { Mongo } from "../database/mongo.js";
import { ObjectId } from "mongodb";

const collectionName = "users";
const authRouter = express.Router();

// Configuração do Passport para autenticação local
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await Mongo.db
          .collection(collectionName)
          .findOne({ email });

        if (!user) {
          return done(null, false, { message: "Invalid email or password" });
        }

        const saltBuffer = Buffer.from(user.salt); // Converte o salt armazenado para Buffer
        const storedPasswordBuffer = Buffer.from(user.password); // Converte a senha armazenada para Buffer

        // Gerar hash da senha fornecida para comparação
        crypto.pbkdf2(
          password,
          saltBuffer,
          310000,
          storedPasswordBuffer.length,
          "sha256",
          (err, hashedPassword) => {
            if (err) return done(err);

            const hashedPasswordBuffer = Buffer.from(hashedPassword); // Converte o hash gerado para Buffer

            // Verifica se os buffers têm o mesmo tamanho antes da comparação
            if (storedPasswordBuffer.length !== hashedPasswordBuffer.length) {
              return done(null, false, {
                message: "Invalid email or password",
              });
            }

            if (
              !crypto.timingSafeEqual(
                storedPasswordBuffer,
                hashedPasswordBuffer
              )
            ) {
              return done(null, false, {
                message: "Invalid email or password",
              });
            }

            const { password, salt, ...userWithoutPassword } = user;
            return done(null, userWithoutPassword);
          }
        );
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Rota de cadastro de usuário
authRouter.post("/signup", async (req, res) => {
  try {
    const { fullname, email, password } = req.body;

    // Verifica se o usuário já existe
    const existingUser = await Mongo.db
      .collection(collectionName)
      .findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    // Gera um salt e hasheia a senha
    const salt = crypto.randomBytes(16);

    crypto.pbkdf2(
      password,
      salt,
      310000,
      32,
      "sha256",
      async (error, hashedPassword) => {
        if (error) {
          return res
            .status(500)
            .json({ success: false, message: "Error hashing password", error });
        }

        // Insere o usuário no banco
        const result = await Mongo.db.collection(collectionName).insertOne({
          fullname,
          email,
          password: hashedPassword,
          salt,
        });

        if (result.insertedId) {
          const user = await Mongo.db
            .collection(collectionName)
            .findOne(
              { _id: new ObjectId(result.insertedId) },
              { projection: { password: 0, salt: 0 } }
            );

          const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET || "secret",
            {
              expiresIn: "1h",
            }
          );

          return res.status(201).json({
            success: true,
            message: "User registered successfully",
            user,
            token,
          });
        }
      }
    );
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Internal server error", error });
  }
});

// Rota de login
authRouter.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Internal Server Error", error: err });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid email or password" });
    }

    // Gera um token para o usuário autenticado
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || "secret",
      {
        expiresIn: "1h",
      }
    );

    return res.status(200).json({
      success: true,
      message: "User logged in successfully",
      user,
      token,
    });
  })(req, res, next);
});

export default authRouter;
