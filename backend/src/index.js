import express from "express";
import cors from "cors";

async function main() {
  const hostname = "localhost";
  const port = 3000;

  const app = express();

  app.use(cors());
  app.use(express.json());

  app.get("/", (req, res) => {
    res.send({
      success: true,
      statusCode: 200,
      body: "farmacia aplication",
    });
  });

  app.listen(port, () => {
    console.log(`Server runing on: http://${hostname}:${port}`);
  });
}

main();
