import express, { response } from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import crypto from 'crypto';

const SBHSStrategy = require('passport-sbhs')

dotenv.config();

const app = express();

mongoose.connect(`${process.env.START_MONGODB}${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}${process.env.END_MONGODB}`, {}, () => {
    console.log("Connected to mongoose successfully")
})

// Middleware 
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }))
app.use(
    session({
        secret: "abc",
        resave: true,
        saveUninitialized: true,
}))

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user:any, done:any) => {
  return done(null, user);
})

passport.deserializeUser((user:any, done:any) => {
  return done(null, user);
})

function base64url_encode(str: any) {
  return str.toString()
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
var code_verifier = base64url_encode(crypto.randomBytes(32));

function sha256(buffer: any) {
  return crypto.createHash('sha256').update(buffer).digest();
}
var code_challenge = base64url_encode(sha256(code_verifier));

// const valid_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// let array = new Uint8Array(40);
// crypto.getRandomValues(array);
// array = array.map(x => valid_chars.charCodeAt(x % valid_chars.length));
// const state = String.fromCharCode.apply(null, array);

passport.use(new SBHSStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    authorizationURL: 'https://student.sbhs.net.au/api/authorize',
    tokenURL: 'https://student.sbhs.net.au/api/token',
    callbackURL: "http://localhost:4000/callback", 
    code_challenge: code_challenge,
    code_challenge_method: "sha256",
    state: "state"
  },
  function(accessToken: any, refreshToken: any, profile: any, cb: any) {
    // Successful Authentication
    cb(null, {access_token: accessToken, user: profile})
  }

));


app.get('/login',
  passport.authenticate('sbhs', { scope: ["all-ro"]}));

app.get('/callback',
  passport.authenticate('sbhs', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('http://localhost:3000');
  });

app.get("/", (req, res) => {
    res.send("Hello World");
})

app.get("/gettokens", (req,res) => {
  // sends user's access token to frontend
  res.send(req.user);
})

app.listen(4000, () => {
    console.log("Server started");
})