import express from "express";
import session from "express-session";
import { existsSync, mkdirSync } from "fs";
import { JSONFileSync, LowSync } from "lowdb";
import base64url from "base64url";
import { randomBytes } from "crypto";
import { getLoginOptions, getRegistrationOptions } from "./webauth.js";
import cors from "cors";
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

process.env.HOSTNAME = "localhost";

if (!existsSync("./.data")) {
  mkdirSync("./.data");
}

const db = new LowSync(new JSONFileSync(".data/db.json"));
db.read();
if (!db.data) {
  db.data = { users: [] };
  db.write();
  db.read();
}

const app = express();
app.set("trust proxy", 1);
app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: false,
    },
  })
);

const corsOptions = cors({
  origin: ["http://localhost:3000", "http://localhost:8080"],
  credentials: true,
  allowedHeaders:
    "Origin,X-Requested-With,Content-Type,Accept,Authorization,X-HTTP-Method-Override,Set-Cookie,Cookie",
});
app.use(express.json());
app.use(corsOptions);

app.options("*", corsOptions);

app.get("/authenticate", (req, res) => {
  const { email, credentialId } = req.query;
  let user = db.data.users.find((u) => u.email === email);

  let isNewUser = false;
  let options = {};

  if (!user) {
    isNewUser = true;
    user = {
      email,
      id: base64url.encode(randomBytes(32)),
      credentials: [],
    };
    db.data.users.push(user);
    db.write();
    db.read();
  }

  options = isNewUser
    ? getRegistrationOptions(user)
    : getLoginOptions(credentialId, user);

  req.session.email = user.email;
  req.session.challenge = options.challenge;
  res.send({
    login: !isNewUser,
    create: isNewUser,
    options,
  });
});

app.post("/create/verify", async (req, res) => {
  const { challenge: expectedChallenge, email } = req.session;
  const expectedRPID = process.env.HOSTNAME;
  const expectedOrigin = "http://localhost:3000";

  try {
    const verification = await verifyRegistrationResponse({
      credential: req.body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
    });

    const { verified, registrationInfo } = verification;

    if (!verified) {
      throw "User verification failed.";
    }

    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    const base64PublicKey = base64url.encode(credentialPublicKey);
    const base64CredentialID = base64url.encode(credentialID);

    const user = db.data.users.find((u) => u.email === email);

    const existingCred = user.credentials.find(
      (cred) => cred.credID === base64CredentialID
    );

    if (!existingCred) {
      user.credentials.push({
        publicKey: base64PublicKey,
        credId: base64CredentialID,
        prevCounter: counter,
      });
    }

    db.write();
    db.read();

    delete req.session.challenge;
    res.json(user);
  } catch (e) {
    delete req.session.challenge;
    delete req.session.email;
    res.status(400).send({ error: e });
  }
});

app.post("/login/verify", async (req, res) => {
  const { body } = req;
  const { email, challenge: expectedChallenge } = req.session;
  const expectedOrigin = "http://localhost:3000";
  const expectedRPID = process.env.HOSTNAME;

  const user = db.data.users.find((u) => u.email === email);

  let existingCredential = user.credentials.find(
    (cred) => cred.credId === req.body.id
  );
  const credential = {};
  credential.credentialPublicKey = base64url.toBuffer(
    existingCredential.publicKey
  );
  credential.credentialID = base64url.toBuffer(existingCredential.credId);
  credential.counter = existingCredential.prevCounter;

  try {
    if (!credential) {
      throw "Authenticating credential not found.";
    }

    const verification = verifyAuthenticationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      authenticator: credential,
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      throw "User verification failed.";
    }

    existingCredential.prevCounter = authenticationInfo.newCounter;

    db.write();

    delete req.session.challenge;
    res.json(user);
  } catch (e) {
    delete req.session.challenge;
    res.status(400).json({ error: e });
  }
});

app.listen(process.env.PORT || 8080, () => {
  console.log("Server is running");
});
