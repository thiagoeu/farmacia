import express from "express";
import cors from "cors";

import { Mongo } from "./database/mongo.js";
import { config } from "dotenv";
import authRouter from "./auth/auth.js";

config();

async function main() {
  const hostname = "localhost";
  const port = 3000;

  const app = express();

  app.use(cors());
  app.use(express.json());

  // DB CONECTION
  const mongoConnection = await Mongo.connect({
    mongoConnectionString: process.env.MONGO_CS,
    mongoDbName: process.env.MONGO_DB_NAME,
  });

  console.log(mongoConnection);

  app.get("/", (req, res) => {
    res.send({
      success: true,
      statusCode: 200,
      body: "farmacia aplication",
    });
  });

  app.use("/auth", authRouter);

  app.listen(port, () => {
    console.log(`Server runing on: http://${hostname}:${port}`);
  });
}

main();
