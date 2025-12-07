import express from "express";
import usersRouter from "./routes/users.js";
import cryptoRouter from "./routes/crypto.js";
import logRouter from "./routes/log.js";
import authenRouter from "./routes/authen.js";
import resourceRouter from "./routes/resource.js";
import vcRouter from "./routes/vc.js";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use("/users", usersRouter);
app.use("/logs", logRouter);
app.use("/crypto", cryptoRouter);
app.use("/auth", authenRouter);
app.use("/resource", resourceRouter);
app.use("/vc", vcRouter);

app.listen(PORT, async () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
