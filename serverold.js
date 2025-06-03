const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const crypto = require("crypto");
const querystring = require("querystring");
const path = require("path");
const session = require("express-session");

dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

// TikTok API credentials
const CLIENT_KEY = process.env.CLIENT_KEY;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

app.use(
  session({
    secret: "&f]}$mIt*rJgl<D8vA-}J`|-RJJf[g+;+}}*.YY+2bs[B0pHT0>z]vcNF#u**Tj&",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// Serve TikTok verification file
app.get("/tiktokL0wjxVG718aNZXgVX8BKnBOQ70GU9NGZ.txt", (req, res) => {
  res.sendFile(
    path.join(__dirname, "tiktokL0wjxVG718aNZXgVX8BKnBOQ70GU9NGZ.txt")
  );
});

// Helper function for PKCE (code challenge & verifier)
function generateCodeVerifier() {
  debugger;
  const codeVerifier = crypto.randomBytes(32).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64");
  const codeChallenge = hash
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  debugger;
  return { codeVerifier, codeChallenge };
}

// Store code_verifier
let storedCodeVerifier = "";

// Redirect user to TikTok OAuth with PKCE
app.get("/login", (req, res) => {
  debugger;
  const { codeVerifier, codeChallenge } = generateCodeVerifier();
  storedCodeVerifier = codeVerifier; // Store code_verifier for later

  const tiktokAuthUrl = `https://www.tiktok.com/v2/auth/authorize/`;
  const queryParams = querystring.stringify({
    client_key: CLIENT_KEY,
    response_type: "code",
    scope: "user.info.basic,user.info.profile,user.info.stats,video.list",
    redirect_uri: REDIRECT_URI,
    state: "12345",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  const fullAuthUrl = `${tiktokAuthUrl}?${queryParams}`;
  console.log("TikTok Authorization URL:", fullAuthUrl);

  res.redirect(fullAuthUrl);
});

// Callback after TikTok login
app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).json({ error: "Missing code from TikTok" });
  }

  try {
    // Exchange authorization code for access token and refresh token
    const tokenResponse = await axios.post(
      "https://open.tiktokapis.com/v2/oauth/token/",
      querystring.stringify({
        client_key: CLIENT_KEY,
        client_secret: CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: REDIRECT_URI,
        code_verifier: storedCodeVerifier,
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    const {
      access_token,
      refresh_token,
      open_id,
      expires_in,
      refresh_expires_in,
    } = tokenResponse.data;

    if (!access_token) {
      return res.status(400).json({ error: "Failed to retrieve access token" });
    }

    // Save tokens and expiration time in session
    req.session.access_token = access_token;
    req.session.refresh_token = refresh_token;
    req.session.open_id = open_id;
    req.session.expires_in = Date.now() + expires_in * 1000; // Save expiration time
    req.session.refresh_expires_in = Date.now() + expires_in * 1000;

    console.log(`Access token: ${access_token}`);
    console.log(
      `Refresh token: ${refresh_token} expires in ${refresh_expires_in}s`
    );

    const userResponse = await axios.get(
      `https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,avatar_url_100,display_name,bio_description,username,following_count,follower_count,likes_count,video_count`,
      {
        headers: { Authorization: `Bearer ${access_token}` },
        params: { open_id: open_id },
      }
    );

    req.session.userInfo = userResponse.data;
    console.log(`User info: ${JSON.stringify(userResponse.data)}`);
    res.redirect("/user-info");
  } catch (error) {
    console.error(
      "Error:",
      error.response ? error.response.data : error.message
    );
    res.status(500).json({ error: "Internal server error" });
  }
});

// Use refresh token to get a new access token
async function refreshAccessToken(req) {
  const refreshToken = req.session.refresh_token;

  if (!refreshToken) {
    throw new Error("No refresh token available");
  }

  try {
    const response = await axios.post(
      "https://open.tiktokapis.com/v2/oauth/token/",
      querystring.stringify({
        client_key: CLIENT_KEY,
        client_secret: CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    const { access_token, expires_in } = response.data;
    req.session.access_token = access_token;
    req.session.expires_in = Date.now() + expires_in * 1000; // Update expiration time

    console.log("New access token:", access_token);
    return access_token;
  } catch (error) {
    console.error(
      "Error refreshing access token:",
      error.response?.data || error.message
    );
    throw new Error("Failed to refresh access token");
  }
}

// Middleware to check if the access token is expired and refresh it
app.use(async (req, res, next) => {
  if (req.session.expires_in && Date.now() > req.session.expires_in) {
    try {
      console.log("Access token expired. Refreshing...");
      await refreshAccessToken(req);
    } catch (error) {
      return res.status(403).json({ error: "Failed to refresh access token" });
    }
  }
  next();
});

// Endpoint to serve user info to the frontend
app.get("/user-info", (req, res) => {
  if (!req.session.userInfo) {
    return res.status(403).json({ error: "User not logged in" });
  }
  res.sendFile(path.join(__dirname, "public", "user.html"));
});

app.get("/api/user-info", (req, res) => {
  if (!req.session.userInfo) {
    return res.status(403).json({ error: "User not logged in" });
  }
  res.json(req.session.userInfo);
});

// Endpoint to fetch TikTok videos (with token check)
app.post("/api/videos", async (req, res) => {
  const accessToken = req.session.access_token;

  if (!accessToken) {
    return res.status(403).json({ error: "User not authenticated" });
  }

  try {
    const response = await axios.post(
      "https://open.tiktokapis.com/v2/video/list/?fields=id,create_time,cover_image_url,share_url,video_description,duration,height,width,title,embed_html,embed_link,like_count,comment_count,share_count,view_count",
      {
        max_count: 20,
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.json(response.data);
    console.log(
      "TikTok VIDEO API response:",
      JSON.stringify(response.data, null, 2)
    );
  } catch (error) {
    console.error(
      "Error fetching videos:",
      error.response ? error.response.data : error.message
    );
    res.status(500).json({ error: "Failed to fetch videos from TikTok API" });
  }
});

app.post("/api/videos/query/by-url", async (req, res) => {
  const accessToken = req.session.access_token;

  if (!accessToken) {
    return res.status(403).json({ error: "User not authenticated" });
  }

  const { video_url } = req.body;

  if (!video_url) {
    return res.status(400).json({ error: "Video URL is required." });
  }

  const videoIdMatch = video_url.match(/\/video\/(\d+)/);
  if (!videoIdMatch) {
    return res.status(400).json({ error: "Invalid video URL." });
  }
  const video_id = videoIdMatch[1];

  try {
    const response = await axios.post(
      `https://open.tiktokapis.com/v2/video/query/?fields=id,create_time,cover_image_url,share_url,video_description,duration,height,width,title,embed_html,embed_link,like_count,comment_count,share_count,view_count`,
      {
        filters: { video_ids: [video_id] },
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log(
      "TikTok VIDEO QUERY API response:",
      JSON.stringify(response.data, null, 2)
    );

    res.json(response.data);
  } catch (error) {
    console.error(
      "Error fetching video details:",
      error.response ? error.response.data : error.message
    );
    res
      .status(500)
      .json({ error: "Failed to fetch video details from TikTok API" });
  }
});

app.use(express.static("public"));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
