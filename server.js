// server.js

const express = require("express");
const sqlite3 = require("sqlite3").verbose(); // Import sqlite3
const cors = require("cors");
const helmet = require("helmet");
const https = require("https");
const fs = require("fs");
const session = require("express-session");
const passport = require("passport");
const nodemailer = require("nodemailer");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken"); // Import jsonwebtoken
require("dotenv").config();
const path = require("path"); // To work with file paths
const { promisify } = require("util");
const multer = require("multer");
const upload = multer();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY); // Import Stripe
const dns = require("dns");
const bcrypt = require("bcrypt");
const app = express();
const fetch = require("node-fetch");
const PORT = process.env.PORT || 2096;

const corsOptions = {
  origin: function (origin, callback) {
    let allowedOrigins = [];

    if (process.env.NODE_ENV === "development") {
      allowedOrigins = [
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5501",
        "http://127.0.0.1:5501",
      ];
    } else if (process.env.NODE_ENV === "production") {
      allowedOrigins = [
        "https://lonewolfit.io:8443",
        "https://www.lonewolfit.io:8443",
        "https://www.lonewolfit.io",
        "https://lonewolfit.io",
      ];
    }

    if (!origin) {
      console.warn("CORS request without origin:", origin); // Log the undefined origin
      callback(null, true); // Allow requests without an Origin header (or handle it as needed)
      return; // Exit the function
    }

    if (allowedOrigins.includes(origin)) {
      callback(null, origin); // Allow the request to this origin
    } else {
      callback(new Error(`Not allowed by CORS: ${origin}`)); // Include the origin in the error
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // Enable preflight for all routes
app.use(helmet());
app.use(express.json({ limit: "20mb" })); // Allow up to 20MB JSON payloads
app.use(express.urlencoded({ limit: "20mb", extended: true })); // Allow URL-encoded data
// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

const db = new sqlite3.Database("./database.sqlite", (err) => {
  if (err) {
    console.error("Error connecting to SQLite database:", err.message);
  } else {
    console.log("Connected to SQLite database.");

    // Create users table if it does not exist, including stripeCustomerId column
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  google_id TEXT UNIQUE,
	  username TEXT,
	  email TEXT UNIQUE NOT NULL,
	  password TEXT,
	  first_name TEXT,
	  middle_name TEXT,
	  last_name TEXT,
	  phone TEXT,         -- Added phone column
	  address TEXT,       -- Added address column
	  profile_photo TEXT, -- Added profile photo column
	  stripeCustomerId TEXT, -- Added Stripe Customer ID column
	  dbaName TEXT,
	  businessAddress TEXT,
	  is_online BOOLEAN DEFAULT 0,
	  last_ping INTEGER,
	  endUserCanEdit BOOLEAN,
	  adminUser BOOLEAN, -- Added Boolean column for user edit permission
	  owner BOOLEAN
	)`,
      (err) => {
        if (err) {
          console.error("Error creating users table:", err.message);
        } else {
          console.log("Users table created or already exists.");
          checkAndAddColumns(); // Call function to check for any missing columns
        }
      }
    );
    // Create testimonials table if it does not exist
    db.run(
      `CREATE TABLE IF NOT EXISTS testimonials (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  user_id INTEGER NOT NULL,
	  testimonial TEXT NOT NULL,
	  approved BOOLEAN DEFAULT 0,
	  FOREIGN KEY (user_id) REFERENCES users (id)
	)`,
      (err) => {
        if (err) {
          console.error("Error creating testimonials table:", err.message);
        } else {
          console.log("Testimonials table created or already exists.");
        }
      }
    );
    //Create a table for users preferences
    db.run(
      `CREATE TABLE IF NOT EXISTS user_preferences (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  user_id INTEGER NOT NULL,
	  preference_key TEXT NOT NULL,
	  preference_value TEXT NOT NULL,
	  FOREIGN KEY (user_id) REFERENCES users (id)
	)`,
      (err) => {
        if (err) {
          console.error("Error creating user_preferences table:", err.message);
        } else {
          console.log("user_preferences table created or already exists.");
        }
      }
    );
    // Create a table for user notifications
    db.run(
      `CREATE TABLE IF NOT EXISTS user_notifications (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  user_id INTEGER NOT NULL,
	  notification_text TEXT NOT NULL,
	  is_read BOOLEAN DEFAULT 0,
	  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	  FOREIGN KEY (user_id) REFERENCES users (id)
	)`,
      (err) => {
        if (err) {
          console.error(
            "Error creating user_notifications table:",
            err.message
          );
        } else {
          console.log("user_notifications table created or already exists.");
        }
      }
    );
    //Create a table for the contact form submissions
    db.run(
      `CREATE TABLE IF NOT EXISTS contact_form_submissions (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  user_id INTEGER,
	  name TEXT NOT NULL,
	  email TEXT,
	  phone TEXT NOT NULL,
	  message TEXT NOT NULL,
	  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	  FOREIGN KEY (user_id) REFERENCES users (id)
	)`,
      (err) => {
        if (err) {
          console.error(
            "Error creating contact_form_submissions table:",
            err.message
          );
        } else {
          console.log(
            "contact_form_submissions table created or already exists."
          );
        }
      }
    );
  }
});

// Function to check and add missing columns
function checkAndAddColumns() {
  const requiredColumns = [
    { name: "phone", type: "TEXT" },
    { name: "address", type: "TEXT" }, // Assuming you mean a single address field
    { name: "profile_photo", type: "TEXT" },
    { name: "stripeCustomerId", type: "TEXT" },
    { name: "dbaName", type: "TEXT" },
    { name: "businessAddress", type: "TEXT" },
    { name: "is_online", type: "BOOLEAN" },
    { name: "last_ping", type: "INTEGER" },
    { name: "endUserCanEdit", type: "BOOLEAN" },
    { name: "adminUser", type: "BOOLEAN" },
    { name: "owner", type: "BOOLEAN" },
  ];

  const query = "PRAGMA table_info(users)";

  db.all(query, [], (err, columns) => {
    if (err) {
      console.error("Error retrieving table schema:", err.message);
      return;
    }

    const existingColumns = columns.map((col) => col.name); // Get a list of existing columns

    // Iterate through required columns and add them if they don't exist
    requiredColumns.forEach((column) => {
      if (!existingColumns.includes(column.name)) {
        db.run(
          `ALTER TABLE users ADD COLUMN ${column.name} ${column.type}`,
          (err) => {
            if (err) {
              console.error(`Error adding column ${column.name}:`, err.message);
            } else {
              console.log(`Column ${column.name} added to users table.`);
            }
          }
        );
      } else {
        console.log(`Column ${column.name} already exists in users table.`);
      }
    });
  });
}

function allowedUsername(username) {
  // Define a regex pattern for allowed characters (alphanumeric, underscores, hyphens)
  const allowedPattern = /^[a-zA-Z0-9_-]+$/;
  return allowedPattern.test(username);
}

let verificationCodes = {}; // To store verification codes temporarily
let tempUsers = {}; // Store temporary user data before verification

// Helper to set a 5-minute expiration for tempUsers and verificationCodes
function setTempUserExpiry(email, minutes = 5) {
  const tempUser = tempUsers[email].email; // Store the temporary user for logging
  setTimeout(() => {
    if (tempUsers[email] && tempUsers[email].email === tempUser.email) {
      console.log(`tempUsers[${email}] expired after ${minutes} minutes.`);
      tempUsers[email] = null;
    }
  }, minutes * 60 * 1000); // Expiration time in ms
}

function setVerificationCodeExpiry(email, minutes = 5) {
  const oldCode = verificationCodes[email]; // Store the old code for logging
  setTimeout(() => {
    if (verificationCodes[email] && verificationCodes[email] === oldCode) {
      console.log(
        `verificationCodes[${email}] expired after ${minutes} minutes.`
      );
      verificationCodes[email] = null;
    }
  }, minutes * 60 * 1000); // Expiration time in ms
}

// Configure email transport using your SMTP settings
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD,
  },
});
app.use(passport.initialize());
app.use(passport.session());

// Passport Google Authentication Configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://lonewolfit.io:2096/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log("Google profile: ", profile);
      try {
        const { id, displayName, emails, name } = profile;
        const email = emails[0].value; // Get the email from the profile
        const firstName = name.givenName;
        const middleName = name.middleName || ""; // Handle any missing middle name
        const lastName = name.familyName;

        console.log(
          `Processing user: ID=${id}, DisplayName=${displayName}, Email=${email}`
        );

        db.get(
          "SELECT * FROM users WHERE google_id = ?",
          [id],
          async (err, user) => {
            if (err) {
              console.error("Error querying user:", err);
              return done(err);
            }

            if (user) {
              console.log(`User found: ${user.username}`);
              if (invalidatedTokens[email]) {
                console.warn("User's token has been invalidated:", email);
                delete invalidatedTokens[email]; // Remove the invalidation status
              }
              return done(null, user); // Existing user, proceed to home/dashboard
            } else {
              console.log("No user found, storing new user temporarily.");

              // Store the new user in a temporary variable
              const tempUser = {
                google_id: id,
                username: displayName,
                email: email,
                first_name: firstName,
                middle_name: middleName,
                last_name: lastName,
              };
              // Return the required data to the done callback
              return done(null, false, {
                tempUserData: tempUser, // Return the temporary user data
              });
            }
          }
        );
      } catch (err) {
        console.error("Error finding or creating user:", err);
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  console.log("Serializing user:", user.email);
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  //console.log(`Deserializing user with ID: ${id}`); // Log the ID being deserialized ONLY IN VERBOSE MODE
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
    if (err) {
      console.error("Error deserializing user:", err);
      return done(err);
    }
    if (!user) {
      console.log(`No user found for ID: ${id}`); // Log if no user is found
      return done(null, false); // User not found
    }
    //console.log("User deserialized successfully:", user.email); // Log successful deserialization (VERBOSE MODE)
    done(null, user); // Provide user details to done
  });
});
let invalidatedTokens = {}; // For production, use a persistent store like Redis or database
function invalidateUserTokens(email) {
  // In this example, we will keep track of invalidated tokens in memory
  invalidatedTokens[email] = Date.now(); // Store an invalidation timestamp

  console.log(`Invalidated tokens for user: ${email}`);
}
// Password reset endpoint
app.post("/api/auth/reset-password", upload.none(), async (req, res) => {
  const { email, verificationCode, newPassword, signOutAllDevices } = req.body;

  // Check the verification code
  if (
    verificationCodes[email] &&
    verificationCodes[email] === verificationCode
  ) {
    // Validate newPassword is provided
    if (!newPassword) {
      return res.status(400).send("New password is required.");
    }
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
    db.run(
      "UPDATE users SET password = ? WHERE email = ?",
      [hashedPassword, email],
      function (err) {
        if (err) {
          console.error("Error updating password:", err);
          return res.status(500).send("Error updating password");
        }

        // Clean up the verification code
        delete verificationCodes[email];

        // Invalidate all existing tokens if signOutAllDevices is true
        if (signOutAllDevices) {
          invalidateUserTokens(email);
        }

        // Fetch the user to generate a new token
        db.get(
          "SELECT id, email FROM users WHERE email = ?",
          [email],
          (err, user) => {
            if (err || !user) {
              console.error("Failed to fetch user for token generation:", err);
              return res.status(500).send("Failed to generate new token");
            }
            console.log("Password reset successfully for email:", email);
            return res.status(200).send("Password updated successfully");
          }
        );
      }
    );
  } else {
    console.log("Invalid verification code entered:", verificationCode);
    if (!verificationCodes[email])
      return res
        .status(404)
        .json({ message: "Verification code does not exist." });
    else return res.status(400).send("Invalid verification code");
  }
});
// JWT middleware with enhanced error logging
const authenticateJWT = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Assuming Bearer token

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        // Check if the token is malformed
        if (err instanceof jwt.JsonWebTokenError) {
          console.warn("JWT verification warning: Malformed token");
          db.run(
            "UPDATE users SET is_online = 0 WHERE email = ?",
            [decoded.email],
            (err) => {
              if (err) {
                console.error("Error updating user status:", err);
              }
            }
          );
          console.log(
            "User status updated to offline due to malformed token:",
            decoded.email
          );
          return res.status(400).json({ message: "Malformed token" });
        }

        // Check if the error is due to token expiration
        if (err.name === "TokenExpiredError") {
          console.warn("JWT verification warning: Token has expired");
          db.run(
            "UPDATE users SET is_online = 0 WHERE email = ?",
            [decoded.email],
            (err) => {
              if (err) {
                console.error("Error updating user status:", err);
              }
            }
          );
          console.log(
            "User status updated to offline due to expired token:",
            decoded.email
          );
          return res.status(403).json({ message: "Token has expired" });
        }

        // Log other verification errors as errors
        console.error("JWT verification error:", err);
        db.run(
          "UPDATE users SET is_online = 0 WHERE email = ?",
          [decoded.email],
          (err) => {
            if (err) {
              console.error("Error updating user status:", err);
            }
          }
        );
        console.log(
          "User status updated to offline due to invalid token:",
          decoded.email
        );
        return res.status(403).json({ message: "Token is not valid" });
      }
      // Check if this token has been invalidated using the email from the decoded JWT
      if (decoded && decoded.email && invalidatedTokens[decoded.email]) {
        db.run(
          "UPDATE users SET is_online = 0 WHERE email = ?",
          [decoded.email],
          (err) => {
            if (err) {
              console.error("Error updating user status:", err);
            }
          }
        );
        console.log(
          "User status updated to offline due to invalidated token:",
          decoded.email
        );
        return res
          .status(401)
          .send("Token has been invalidated. Please log in again.");
      }
      req.user = decoded; // Save the decoded user info for further use
      next(); // Proceed to the next middleware/route handler
    });
  } else {
    return res.sendStatus(403); // Forbidden
  }
};

// Function to generate a JWT
const generateJWT = (user) => {
  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  console.log("Generated JWT:", token);
  return token;
};
function checkAdminStatus(email) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
      if (err) {
        console.error("Database error while checking email:", err);
        return resolve(false);
      }

      if (!user) {
        console.error("Email does not exist in our records.");
        return resolve(false);
      }

      // Return admin status
      resolve(user.adminUser ? user.adminUser : false);
    });
  });
}
function checkAdminStatusByID(userId) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
      if (err) {
        console.error("Database error while checking userId:", err);
        return resolve(false);
      }

      if (!user) {
        console.error("USERID does not exist in our records.");
        return resolve(false);
      }

      // Return admin status
      resolve(user.adminUser ? user.adminUser : false);
    });
  });
}
function checkOwnerStatusByID(userId) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
      if (err) {
        console.error("Database error while checking userId:", err);
        return resolve(false);
      }

      if (!user) {
        console.error("USERID does not exist in our records.");
        return resolve(false);
      }

      // Return admin status
      resolve(user.owner ? user.owner : false);
    });
  });
}
// In-memory store for redirect URIs keyed by a temporary token.
const redirectUriStore = {};

// Step 1: When starting OAuth, capture the redirect_uri and store it using a temporary key.
app.get("/auth/google", (req, res, next) => {
  // Grab redirect_uri from the query parameters
  const redirectUri = req.query.redirect_uri;
  //Verify that the redirectUri is a valid URL and on the same domain
  const allowedHtmlRegex = /^\/?[a-zA-Z0-9_-]+\.html$/i;
  if (redirectUri && !allowedHtmlRegex.test(redirectUri)) {
    return res.status(400).send("Invalid redirect_uri");
  }
  // Generate a random temporary key (using crypto)
  const tempKey = require("crypto").randomBytes(16).toString("hex");
  // Store the redirect URI in our in‑memory store using the temp key.
  redirectUriStore[tempKey] = redirectUri;
  console.log(`Stored redirect URI for token ${tempKey}: ${redirectUri}`);

  // Launch authentication with Passport—pass in the temp key as the "state" parameter
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
    state: tempKey,
  })(req, res, next);
});

app.get("/auth/google/callback", (req, res, next) => {
  console.log("Google Authentication Callback Triggered");
  // Retrieve our temporary key from the state parameter.
  const tempKey = req.query.state;

  // Extract the stored redirect URI or use a default.
  const redirectUri = redirectUriStore[tempKey] || null;
  // Authenticate with google
  passport.authenticate("google", (err, user, info) => {
    if (err) {
      console.error("Error during authentication:", err);
      return next(err);
    }
    if (!user) {
      // Handle case where the user does not exist in the database
      if (info && info.tempUserData) {
        // Store email in tempUsers
        tempUsers[info.tempUserData.email] = info.tempUserData;
        // Set an expiration for the temporary user data
        setTempUserExpiry(info.tempUserData.email, 5); // 5 minutes expiration
        console.log(
          "Temporary user data stored in tempUsers:",
          tempUsers[info.tempUserData.email]
        );
      }
      // Redirect to create account with email as a query parameter
      console.log(
        "No existing user found, redirecting to create_google_account.html with email."
      );
      if (redirectUri)
        return res.redirect(
          `https://www.lonewolfit.io/create_google_account.html?email=${info.tempUserData.email}&redirect_uri=${redirectUri}`
        );
      else
        return res.redirect(
          `https://www.lonewolfit.io/create_google_account.html?email=${info.tempUserData.email}`
        );
    }

    // Log the user in using session management
    req.logIn(user, (err) => {
      if (err) {
        console.error("Error logging in user:", err);
        return next(err);
      }

      // Generate a new JWT token for the logged-in user
      const token = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      db.run(
        "UPDATE users SET is_online = 1, last_ping = ? WHERE email = ?",
        [Date.now(), user.email],
        (err) => {
          if (err)
            console.error("Error setting user online status:", err.message);
        }
      );
      console.log("User status updated to online for email:", user.email);
      console.log(
        `User logged in: ${user.username}, Generated token: ${token}`
      );
      checkAdminStatusByID(user.id)
        .then((admin) => {
          console.log(redirectUri);
          return res.redirect(
            `https://www.lonewolfit.io/login.html?token=${token}&admin=${admin}&redirect_uri=${redirectUri}`
          );
        })
        .catch((error) => {
          console.error("Error determining admin status: ", error);
          return next(error);
        });
    });
  })(req, res, next);
});

// Sample API Endpoint to test database connectivity
app.get("/api/test", (req, res) => {
  console.log("API test endpoint reached.");
  res.json({ message: "SQLite is working!" });
});

app.post("/api/auth/user-temp-data", (req, res) => {
  console.log("OPTIONS request received for user-temp-data");
  const { email } = req.body; // Get the email from the request body
  console.log("Received request for temporary user data for:", email);

  if (tempUsers[email]) {
    console.log("Temporary user data found:", tempUsers[email]);
    const tempUser = tempUsers[email];
    tempUsers[email] = null; // Clear the temporary user data after sending it
    console.log("Temporary user data cleared for:", email);
    res.json(tempUser); // Send the temp user data back to the client
  } else {
    console.log("No temporary user data available for:", email);
    res.status(404).send("No temporary user data available.");
  }
});
app.post(
  "/api/auth/register-google-account",
  upload.none(),
  async (req, res) => {
    const {
      google_id,
      firstName,
      middleName,
      lastName,
      phone,
      address,
      username,
      email,
      dbaName,
      businessAddress,
    } = req.body;

    // Define required fields
    const requiredFields = [
      "google_id",
      "firstName",
      "lastName",
      "phone",
      "address",
      "username",
      "email",
    ];

    // Validate required fields
    for (const field of requiredFields) {
      if (!req.body[field]) {
        return res
          .status(400)
          .json({ message: `Missing required field: ${field}` });
      }
    }

    if (!allowedUsername(username)) {
      return res
        .status(400)
        .send(
          "Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed."
        );
    }

    try {
      // Check if the user already exists by email
      db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, existingUser) => {
          if (err) {
            console.error("Database error while checking email:", err);
            return res.status(500).send("Error checking email existence");
          }

          if (existingUser) {
            console.log("Email already exists:", email);
            return res.status(400).send("Email already exists");
          }

          // Check if the username already exists
          db.get(
            "SELECT * FROM users WHERE username = ?",
            [username],
            async (err, existingUsername) => {
              if (err) {
                console.error("Database error while checking username:", err);
                return res
                  .status(500)
                  .send("Error checking username existence");
              }

              if (existingUsername) {
                console.log("Username already exists:", username);
                return res.status(400).send("Username already exists");
              }

              // Parse the address string
              const addressParts = address
                .split(",")
                .map((part) => part.trim());
              const stripeAddress = {
                line1: addressParts[0] || "",
                line2: addressParts[1] || "", // Optional
                city: addressParts[2] || "",
                state: addressParts[3] || "",
                postal_code: addressParts[4] || "",
                country: addressParts[5] || "",
              };

              // Create a new Stripe customer
              try {
                // Build metadata, ensuring all values are strings and filtering out undefined/null
                const rawMetadata = {
                  username,
                  dbaName,
                  businessAddress,
                  endUserCanEdit: String(true),
                };
                const metadata = Object.fromEntries(
                  Object.entries(rawMetadata).filter(
                    ([_, v]) => v !== undefined && v !== null
                  )
                );
                const customer = await stripe.customers.create({
                  email: email,
                  name: `${firstName} ${lastName}`,
                  phone: phone,
                  address: stripeAddress, // Use structured address here
                  metadata,
                });

                console.log(`Stripe customer created: ${customer.id}`);

                // Proceed with the registration inserting the Stripe customer id into the DB
                db.run(
                  "INSERT INTO users (google_id, first_name, middle_name, last_name, phone, address, username, email, profile_photo, stripeCustomerId, dbaName, businessAddress, endUserCanEdit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  [
                    google_id,
                    firstName,
                    middleName,
                    lastName,
                    phone,
                    address,
                    username,
                    email,
                    null,
                    customer.id,
                    dbaName,
                    businessAddress,
                    true,
                  ],
                  function (err) {
                    if (err) {
                      console.error("Registration error:", err);
                      return res.status(500).json({ message: err.message });
                    } else {
                      console.log("User registered:", {
                        id: this.lastID,
                        username,
                        email,
                      });
                      // Generate a JWT token and send it back
                      const token = generateJWT({
                        id: this.lastID,
                        email,
                        username,
                      });
                      return res.status(201).json({ email, token });
                    }
                  }
                );
              } catch (stripeError) {
                console.error("Error creating Stripe customer:", stripeError);
                return res.status(500).json({ message: stripeError.message });
              }
            }
          );
        }
      );
    } catch (err) {
      console.error("Error registering user:", err);
      return res.status(500).send("Error registering user: " + err.message);
    }
  }
);

const mxLookupWithTimeout = async (domain, timeoutMs) => {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("MX lookup timed out"));
    }, timeoutMs);

    dns.resolveMx(domain, (err, mxRecords) => {
      clearTimeout(timeout);
      if (err) {
        return reject(err);
      }
      resolve(mxRecords);
    });
  });
};

// Update the register endpoint to handle file uploads
app.post("/api/auth/register", upload.none(), async (req, res) => {
  const {
    firstName,
    middleName,
    lastName,
    phone,
    address,
    username,
    email,
    password,
    dbaName,
    businessAddress,
    turnstileToken,
  } = req.body;

  // Define required fields
  const requiredFields = [
    "firstName",
    "lastName",
    "phone",
    "address",
    "username",
    "email",
    "password",
    "dbaName",
    "businessAddress",
  ];

  // Validate required fields
  for (const field of requiredFields) {
    if (!req.body[field]) {
      return res
        .status(400)
        .json({ message: `Missing required field: ${field}` });
    }
  }

  //Validate username format
  if (!allowedUsername(username)) {
    return res
      .status(400)
      .send(
        "Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed."
      );
  }

  // Validate email format (basic)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).status("Invalid email address");
  }

  // Require Turnstile token
  if (!turnstileToken && process.env.TURNSTILES_ENABLED === "true") {
    return res.status(400).send("Missing captcha token.");
  }

  // Verify Turnstile token with Cloudflare
  if (process.env.TURNSTILES_ENABLED === "true") {
    try {
      const verifyUrl =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";
      const params = new URLSearchParams();
      params.append("secret", process.env.TURNSTILE_SECRET);
      params.append("response", turnstileToken);
      // optional: params.append("remoteip", req.ip);

      const verifyRes = await fetch(verifyUrl, {
        method: "POST",
        body: params,
      });
      const verifyJson = await verifyRes.json();
      if (!verifyJson.success) {
        console.warn("Turnstile verify failed:", verifyJson);
        return res.status(403).send("Captcha verification failed.");
      }
    } catch (err) {
      console.error("Turnstile verification error:", err);
      return res.status(500).send("Captcha verification error: " + err.message);
    }
  }

  // Check if the domain has MX records
  const emailDomain = email.split("@")[1];

  try {
    const mxRecords = await mxLookupWithTimeout(emailDomain, 10000); // 10 seconds timeout
    if (!mxRecords || mxRecords.length === 0) {
      return res.status(400).json({
        message: "The email domain does not have valid mail records.",
      });
    }
  } catch (error) {
    console.error("Error checking MX records:", error.message);
    return res.status(400).json({
      message: "Email domain verification failed: " + error.message,
    });
  }
  try {
    // Check if the user already exists by email
    db.get(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, existingUser) => {
        if (err) {
          console.error("Database error while checking email:", err);
          return res
            .status(500)
            .send("Error checking email existence: " + err.message);
        }

        if (existingUser) {
          console.log("Email already exists:", email);
          return res.status(400).send("Email already exists");
        }

        // Check if the username already exists
        db.get(
          "SELECT * FROM users WHERE username = ?",
          [username],
          async (err, existingUsername) => {
            if (err) {
              console.error("Database error while checking username:", err);
              return res
                .status(500)
                .send("Error checking username existence: " + err.message);
            }

            if (existingUsername) {
              console.log("Username already exists:", username);
              return res.status(400).send("Username already exists");
            }

            try {
              // Proceed with the registration and hashing of the password
              const hashedPassword = await bcrypt.hash(password, 10);
              tempUsers[email] = {
                firstName,
                middleName,
                lastName,
                phone,
                address,
                username,
                hashedPassword,
                profilePhoto: null,
                dbaName: dbaName,
                businessAddress: businessAddress,
              };
              setTempUserExpiry(email); // Set expiration for temp user data
              console.log("Temporary user data stored for:", email);

              const verificationCode = Math.floor(
                100000 + Math.random() * 900000
              ).toString();
              verificationCodes[email] = verificationCode;
              setVerificationCodeExpiry(email);

              const mailOptions = {
                from: process.env.EMAIL,
                to: email,
                subject: "Verification Code",
                text: `Your verification code is ${verificationCode}`,
              };

              transporter.sendMail(mailOptions, (error) => {
                if (error) {
                  console.error("Error sending email:", error);
                  return res
                    .status(500)
                    .send("Error sending verification email: " + error.message);
                }
                console.log("Verification code sent to:", email);
                return res
                  .status(201)
                  .send("User registered. Verification code sent to email.");
              });
            } catch (stripeError) {
              console.error("Error creating Stripe customer:", stripeError);
              return res.status(500).json({
                message:
                  "Failed to create Stripe customer: " + stripeError.message,
              });
            }
          }
        );
      }
    );
  } catch (err) {
    console.error("Error registering user:", err);
    return res.status(500).send("Error registering user");
  }
});

// In the verification flow, save the user in the database including their info and profile photo path.
app.post("/api/auth/verify-registration", async (req, res) => {
  const { email, code } = req.body;

  if (verificationCodes[email] && verificationCodes[email] === code) {
    if (tempUsers[email]) {
      const {
        firstName,
        middleName,
        lastName,
        phone,
        address,
        username,
        hashedPassword,
        profilePhoto,
        dbaName,
        businessAddress,
      } = tempUsers[email];

      // Parse the address string
      const addressParts = address.split(",").map((part) => part.trim());
      const stripeAddress = {
        line1: addressParts[0] || "",
        line2: addressParts[1] || "", // Optional
        city: addressParts[2] || "",
        state: addressParts[3] || "",
        postal_code: addressParts[4] || "",
        country: addressParts[5] || "",
      };

      try {
        // Build metadata, ensuring all values are strings and filtering out undefined/null
        const rawMetadata = {
          username,
          dbaName,
          businessAddress,
          endUserCanEdit: String(true),
        };
        const metadata = Object.fromEntries(
          Object.entries(rawMetadata).filter(
            ([_, v]) => v !== undefined && v !== null
          )
        );
        const customer = await stripe.customers.create({
          email: email,
          name: `${firstName} ${lastName}`,
          phone: phone,
          address: stripeAddress, // Use structured address here
          metadata,
        });

        console.log(`Stripe customer created: ${customer.id}`);

        let stripeCustomerId = customer.id;

        db.run(
          "INSERT INTO users (first_name, middle_name, last_name, phone, address, username, email, password, profile_photo, stripeCustomerId, dbaName, businessAddress, endUserCanEdit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          [
            firstName,
            middleName,
            lastName,
            phone,
            address,
            username,
            email,
            hashedPassword,
            profilePhoto,
            stripeCustomerId,
            dbaName,
            businessAddress,
            true,
          ],
          function (err) {
            if (err) {
              console.error("Registration error:", err);
              return res.status(500).json({ message: err.message });
            } else {
              console.log("User registered:", {
                id: this.lastID,
                username,
                email,
              });
              delete verificationCodes[email];
              delete tempUsers[email];

              return res.status(201).json({ id: this.lastID, username, email });
            }
          }
        );
      } catch (error) {
        console.error("Stripe error:", error);
        return res.status(500).json({
          message: "Failed to create Stripe customer: " + error.message,
        });
      }
    } else {
      console.log("No temporary registration found for this email:", email);
      return res
        .status(400)
        .json({ message: "No temporary registration found for this email." });
    }
  } else {
    console.log("Invalid verification code entered:", code);
    if (!verificationCodes[email])
      return res
        .status(404)
        .json({ message: "Verification code does not exist." });
    else return res.status(400).json({ message: "Invalid verification code" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt for email:", email);

  // Check if the user exists among temporary users first
  if (tempUsers[email]) {
    console.log(
      "User found in temporary storage. Sending registration verification code."
    );

    // User found in temporary storage, prompt to verify by sending code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();
    verificationCodes[email] = verificationCode;

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Registration Verification Code",
      text: `Your verification code for registration is ${verificationCode}.`,
    };

    // Send verification email
    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).send("Error sending verification email");
      }
      console.log("Verification code sent for registration to:", email);
      return res
        .status(200)
        .send(
          "Verification code sent for registration. Please check your email."
        );
    });
  } else {
    // If user is not in temporary storage, check in the main database
    db.get(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, user) => {
        if (err) {
          console.error("Login error:", err);
          return res.status(500).send("Server Error");
        }

        if (user) {
          console.log("User found in database, checking password for:", email);
          if (!user.password && user.google_id) {
            // User is authenticated via Google
            console.log(
              "User authenticated via Google, no password check needed."
            );
            return res
              .status(404)
              .send(
                "Password not found in database. User authenticated via Google. Please log in with Google."
              );
          }
          // Check password
          const match = await bcrypt.compare(password, user.password);
          if (match) {
            console.log("Password matched for user:", email);

            // Password matches, send verification code
            const verificationCode = Math.floor(
              100000 + Math.random() * 900000
            ).toString();
            verificationCodes[email] = verificationCode;
            setVerificationCodeExpiry(email);

            const mailOptions = {
              from: process.env.EMAIL,
              to: email,
              subject: "Login Verification Code",
              text: `Your login verification code is ${verificationCode}.`,
            };

            transporter.sendMail(mailOptions, (error) => {
              if (error) {
                console.error("Error sending email:", error);
                return res
                  .status(500)
                  .send("Error sending verification email: " + error.message);
              }
              console.log("Verification code sent for login to:", email);
              return res
                .status(200)
                .send(
                  "Verification code sent for login. Please check your email."
                );
            });
          } else {
            console.log("Incorrect password for user:", email);
            // Incorrect password
            return res.status(401).json({ message: "Invalid credentials" });
          }
        } else {
          console.log("No user found for:", email);
          return res.status(401).json({ message: "Invalid credentials" });
        }
      }
    );
  }
});

// New endpoint to verify login code
// New endpoint to verify login code
app.post("/api/auth/verify-login", (req, res) => {
  const { email, code } = req.body;

  if (verificationCodes[email] && verificationCodes[email] === code) {
    db.get(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, user) => {
        if (err) {
          console.error("Error fetching user:", err);
          return res.status(500).send("Server Error: Cannot fetch user");
        }
        const token = await generateJWT(user); // Generate JWT on successful verification
        const adminUser = await checkAdminStatus(email);
        delete verificationCodes[email]; // Clean up our stored code
        if (invalidatedTokens[email]) {
          console.warn("User's token has been invalidated:", email);
          delete invalidatedTokens[email]; // Remove the invalidation status
        }
        db.run(
          "UPDATE users SET is_online = 1, last_ping = ? WHERE email = ?",
          [Date.now(), email],
          (err) => {
            if (err)
              console.error("Error setting user online status:", err.message);
          }
        );
        console.log("User status updated to online for email:", email);
        res.json({ user, token, adminUser }); // Return user info and token
      }
    );
  } else {
    // Check to see if user exists in the database
    if (!verificationCodes[email])
      return res
        .status(404)
        .json({ message: "Verification code does not exist." });
    else return res.status(400).json({ message: "Invalid verification code" });
  }
});
// Resend Verification Code Endpoint
app.post("/api/auth/resend-verification", (req, res) => {
  const { email } = req.body;
  console.log("Resend verification code request for email:", email);

  // Check if email exists in temporary users
  if (tempUsers[email]) {
    console.log(
      "User found in temporary storage, resending verification code."
    );

    // User is in the temporary list, resend verification code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();
    verificationCodes[email] = verificationCode; // Store it in memory
    setVerificationCodeExpiry(email); // Set expiry for the code

    // Send the verification code again
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Verification Code",
      text: `Your verification code is ${verificationCode}`,
    };

    // Send email
    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).send("Error sending verification email");
      }
      console.log("Verification code resent to:", email);
      return res
        .status(200)
        .send("Verification code resent. Please check your email.");
    });
  } else {
    // Check if the user exists in the database
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send("Server Error");
      }

      // If the user does not exist, return a not found message.
      if (!user) {
        console.log("No user found with email:", email);
        return res.status(404).json({ message: "User not found." });
      }

      // User exists in the database, notify that the user is already registered
      console.log("User already registered for email:", email);
      return res.status(400).json({
        message:
          "User has already completed registration. Cannot resend verification code.",
      });
    });
  }
});
// Resend Login Verification Code Endpoint
app.post("/api/auth/resend-verification-login", (req, res) => {
  const { email } = req.body;
  console.log("Resend login verification code request for email:", email);

  // Only allow resending if the user exists in the database (not tempUsers)
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Server Error");
    }

    if (!user) {
      console.log("No user found with email:", email);
      return res.status(404).json({ message: "User not found." });
    }

    // Generate and store a new login verification code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();
    verificationCodes[email] = verificationCode;
    setVerificationCodeExpiry(email); // Set expiry for the code

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Login Verification Code",
      text: `Your login verification code is ${verificationCode}.`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).send("Error sending verification email");
      }
      console.log("Login verification code resent to:", email);
      return res
        .status(200)
        .send("Login verification code resent. Please check your email.");
    });
  });
});

// Add this endpoint to check authentication status
app.get("/api/auth/check-auth", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.get(
    "SELECT id, email, first_name, last_name, stripeCustomerId, dbaName, adminUser FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err || !user) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Server Error");
      }
      if (user.email && invalidatedTokens[user.email]) {
        db.run(
          "UPDATE users SET is_online = 0 WHERE email = ?",
          [user.email],
          (err) => {
            if (err) console.error("Error updating user status:", err.message);
          }
        );
        console.log(
          "User status updated to offline due to invalidated token:",
          user.email
        );
        console.warn("User's token has been invalidated:", user.email);
        invalidatedTokens[user.email] = null;
        return res.status(401).json({ message: "Token has been invalidated." });
      }
      // Respond with the user's authentication status and relevant data
      res.json({
        isAuthenticated: true,
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          stripeCustomerId: user.stripeCustomerId, // Include Stripe Customer ID
          dbaName: user.dbaName,
          adminUser: user.adminUser,
        },
      });
    }
  );
});

app.post("/api/auth/sign-out", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const { doNotSignOutAllDevices } = req.body;

  // Fetch the user's email from the database using their userId
  db.get("SELECT email FROM users WHERE id = ?", [userId], (err, row) => {
    if (err || !row) {
      console.error("Error fetching user email for sign-out:", err);
      return res.status(500).send("Error fetching user email for sign-out");
    } else {
      db.run(
        "UPDATE users SET is_online = 0 WHERE email = ?",
        [row.email],
        (err) => {
          if (err)
            console.error("Error setting user online status:", err.message);
        }
      );
      console.log("User status updated to offline for email:", row.email);
      if (!doNotSignOutAllDevices) {
        // Invalidate all tokens for this user (sign out everywhere)
        invalidateUserTokens(row.email);
        console.log("All devices signed out for:", row.email);
      } else {
        // Only sign out this session (do not invalidate all tokens)
        console.log("Only current session signed out for:", row.email);
      }
    }
  });

  // Optionally, you can also destroy the session
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Error ending session");
    }

    console.log("Session destroyed successfully.");
    res.status(200).send("User logged out successfully");
  });
});

// Helper function to destroy session and handle token invalidation
function destroySession({ token, doNotSignOutAllDevices, req, res }) {
  if (!token) {
    return res.status(400).send("Token is required to destroy session");
  }
  // Verify the token
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("Invalid token:", err);
      return res.status(403).send("Invalid token");
    }
    if (user && user.id && user.email && !doNotSignOutAllDevices) {
      invalidateUserTokens(user.email);
      console.log("All sessions destroyed for:", user.email);
    } else {
      // Only sign out this session (do not invalidate all tokens)
      console.log("Only current session destroyed for:", user.email);
    }
    db.run(
      "UPDATE users SET is_online = 0 WHERE email = ?",
      [user.email],
      (err) => {
        if (err) console.error("Error updating user status:", err.message);
      }
    );
    console.log("User status updated to offline for:", user.email);
    // If valid, destroy the session
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res.status(500).send("Error ending session");
      }
      console.log("Session destroyed successfully.");
      return res.status(200).send("Session destroyed successfully");
    });
  });
}

app.post("/api/auth/destroy-session", (req, res) => {
  // Grab the token, and doNotSignOutAllDevices from the request body
  const { token, doNotSignOutAllDevices } = req.body;
  return destroySession({ token, doNotSignOutAllDevices, req, res });
});
app.post("/api/user/ping", (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).send("Token is required to ping user");
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || !decoded)
      return destroySession({ token, doNotSignOutAllDevices: false, req, res });
    db.run("UPDATE users SET is_online = 1, last_ping = ? WHERE id = ?", [
      Date.now(),
      decoded.id,
    ]);
    console.log(
      "User pinged successfully, updated online status for user ID:",
      decoded.id
    );
    res.sendStatus(200);
  });
});
// Periodically mark users offline if last_ping is too old
setInterval(() => {
  const cutoff = Date.now() - 3 * 60 * 1000; // 3 minutes ago
  db.all("SELECT * FROM users WHERE last_ping < ?", [cutoff], (err, users) => {
    if (err) {
      console.error("Error updating user status:", err);
    }
    users.forEach((row) => {
      if (!row.is_online) return; // Skip if already offline
      db.run("UPDATE users SET is_online = 0 WHERE id = ?", [row.id], (err) => {
        if (err) console.error("Error updating user status:", err.message);
      });
      console.log("User marked offline:", row.id);
      invalidateUserTokens(row.email);
      console.log("All sessions invalidated for:", row.email);
    });
  });
}, 3 * 60 * 1000); // every 3 minutes
app.delete("/api/admin/delete-account", authenticateJWT, async (req, res) => {
  const userId = req.user.id;

  const { editorId } = req.body;

  if (!editorId)
    return res
      .status(400)
      .json({ error: "EDITOR ID required to delete account..." });

  const admin = await checkAdminStatusByID(userId);
  const editorAdmin = await checkAdminStatusByID(editorId);
  if (!admin) {
    return res
      .status(400)
      .json({ error: "USER IS NOT AN APPROVED ADMIN OF LONE WOLF IT..." });
  } else if (editorAdmin) {
    return res.status(400).json({ error: "Admins cannot delete admins..." });
  }

  // First, retrieve the user's profile photo path and Stripe customer ID from the database
  db.get(
    "SELECT profile_photo, stripeCustomerId FROM users WHERE id = ?",
    [editorId],
    (err, user) => {
      if (err) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Server Error");
      }

      // Check if user exists
      if (!user) {
        return res.status(404).send("User not found");
      }

      const profilePhotoPath = user.profile_photo;
      const stripeCustomerId = user.stripeCustomerId;

      // Delete the user from Stripe using the Stripe customer ID
      if (stripeCustomerId) {
        stripe.customers.del(stripeCustomerId, (stripeErr) => {
          if (stripeErr) {
            console.error("Error deleting customer from Stripe:", stripeErr);
            return res.status(500).send("Failed to delete user from Stripe");
          }
          console.log("Customer removed from Stripe:", stripeCustomerId);
        });
      }

      // Delete the user's account from the database
      db.run("DELETE FROM users WHERE id = ?", [editorId], function (err) {
        if (err) {
          console.error("Error deleting user:", err);
          return res.status(500).send("Server Error");
        }

        console.log("User account deleted:", editorId);

        // If a profile photo exists, delete it from the filesystem
        if (profilePhotoPath) {
          fs.unlink(profilePhotoPath, (err) => {
            if (err) {
              console.error("Error deleting profile photo:", err);
            } else {
              console.log("Profile photo deleted:", profilePhotoPath);
            }
          });
        }

        // Use req.logout first then switch to session destruction
        req.logout((err) => {
          if (err) {
            console.error("Error during logout:", err);
            return res.status(500).send("Error during logout");
          }

          // Now destroy the session
          req.session.destroy((err) => {
            if (err) {
              console.error("Error destroying session:", err);
              return res.status(500).send("Error ending session");
            }

            console.log("Session destroyed successfully.");
            res.status(200).send("User account deleted successfully");
          });
        });
      });
    }
  );
});
app.delete("/api/auth/delete-account", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  // First, retrieve the user's profile photo path and Stripe customer ID from the database
  db.get(
    "SELECT profile_photo, stripeCustomerId FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Server Error");
      }

      // Check if user exists
      if (!user) {
        return res.status(404).send("User not found");
      }

      const profilePhotoPath = user.profile_photo;
      const stripeCustomerId = user.stripeCustomerId;

      // Delete the user from Stripe using the Stripe customer ID
      if (stripeCustomerId) {
        stripe.customers.del(stripeCustomerId, (stripeErr) => {
          if (stripeErr) {
            console.error("Error deleting customer from Stripe:", stripeErr);
            return res.status(500).send("Failed to delete user from Stripe");
          }
          console.log("Customer removed from Stripe:", stripeCustomerId);
        });
      }

      // Delete the user's account from the database
      db.run("DELETE FROM users WHERE id = ?", [userId], function (err) {
        if (err) {
          console.error("Error deleting user:", err);
          return res.status(500).send("Server Error");
        }

        console.log("User account deleted:", userId);

        // If a profile photo exists, delete it from the filesystem
        if (profilePhotoPath) {
          fs.unlink(profilePhotoPath, (err) => {
            if (err) {
              console.error("Error deleting profile photo:", err);
            } else {
              console.log("Profile photo deleted:", profilePhotoPath);
            }
          });
        }

        // Use req.logout first then switch to session destruction
        req.logout((err) => {
          if (err) {
            console.error("Error during logout:", err);
            return res.status(500).send("Error during logout");
          }

          // Now destroy the session
          req.session.destroy((err) => {
            if (err) {
              console.error("Error destroying session:", err);
              return res.status(500).send("Error ending session");
            }

            console.log("Session destroyed successfully.");
            res.status(200).send("User account deleted successfully");
          });
        });
      });
    }
  );
});
// Function to get all users from the database
const getAllUsers = async () => {
  return new Promise((resolve, reject) => {
    db.all(`SELECT * FROM users`, [], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
};

app.get("/api/users", authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  try {
    const admin = await checkAdminStatusByID(userId);
    if (!admin) {
      return res
        .status(400)
        .send({ error: "USER IS NOT AN APPROVED ADMIN OF LONE WOLF IT..." });
    }
    const users = await getAllUsers();
    return res.status(200).json(users);
  } catch (error) {
    console.error(`Error retrieving users: ${error}`);
    return res
      .status(500)
      .send({ error: "An error occurred while retrieving users" });
  }
});

app.get("/api/user/invoices", authenticateJWT, async (req, res) => {
  const userId = req.user.id;

  db.get(
    "SELECT email, stripeCustomerId FROM users WHERE id = ?",
    [userId],
    async (err, user) => {
      if (err || !user) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Server Error");
      }

      try {
        const invoices = await stripe.invoices.list({
          customer: user.stripeCustomerId, // Use customer ID from database
        });

        console.log("Invoices retrieved for user:", user.email);
        res.json(invoices);
      } catch (error) {
        console.error("Error fetching invoices from Stripe:", error);
        res.status(500).send("Stripe Error");
      }
    }
  );
});

app.get("/api/user/payments", authenticateJWT, async (req, res) => {
  const userId = req.user.id;

  db.get(
    "SELECT email, stripeCustomerId FROM users WHERE id = ?",
    [userId],
    async (err, user) => {
      if (err || !user) {
        console.error("Error fetching user:", err);
        return res.status(500).send("Server Error");
      }

      try {
        const payments = await stripe.paymentIntents.list({
          customer: user.stripeCustomerId, // Use customer ID from database
          expand: ["data.charges"],
        });

        console.log("Payments retrieved for user:", user.email);
        res.json(payments);
      } catch (error) {
        console.error("Error fetching payments from Stripe:", error);
        res.status(500).send("Stripe Error");
      }
    }
  );
});

app.get("/api/auth/get-user-details", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.get(
    "SELECT first_name, middle_name, last_name, username, phone, address, email, profile_photo, stripeCustomerId, dbaName, businessAddress, endUserCanEdit FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err) {
        console.error("Error fetching user details from DB:", err);
        return res.status(500).json({ message: err.message });
      }

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Log the user data to verify proper fetching
      console.log("Fetched user details:", user.email);

      res.json(user); // Send user data back as JSON
    }
  );
});

// GET '/api/auth/get-user-details'
app.post("/api/auth/get-user-details/withouttoken", (req, res) => {
  const { userId } = req.body; // Get userId from the request body

  if (!userId) {
    console.log("User ID not provided in the request body.");
    return res.status(400).json({ message: "User ID is required" });
  }

  db.get(
    "SELECT first_name, last_name, address, profile_photo, dbaName, businessAddress FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err) {
        console.error("Error fetching user details from DB:", err);
        return res.status(500).json({ message: err.message });
      }

      if (!user) {
        console.log(`User not found for ID: ${userId}`);
        return res.status(404).json({ message: "User not found" });
      }

      // Extract city and state from the address
      const addressParts = user.address ? user.address.split(",") : [];
      const city = addressParts[2] ? addressParts[2].trim() : ""; // Assuming city is the second part
      const state = addressParts[3] ? addressParts[3].trim() : ""; // Assuming state is the third part
      const country = addressParts[5] ? addressParts[5].trim() : "";
      // Construct the response object with only required fields
      const userData = {
        id: userId,
        first_name: user.first_name,
        last_name: user.last_name,
        city: city,
        state: state,
        country: country,
        profile_photo: user.profile_photo,
        dbaName: user.dbaName,
        businessAddress: user.businessAddress,
      };

      // Log the user data to verify proper fetching
      //console.log('Fetched user details without token for user:', userId);

      res.json(userData); // Send filtered user data back as JSON
    }
  );
});

app.put("/api/admin/edit-user", authenticateJWT, async (req, res) => {
  const {
    editorId,
    firstName,
    middleName,
    lastName,
    phone,
    address,
    username,
    email,
    stripeCustomerId,
    dbaName,
    businessAddress,
    endUserCanEdit,
    adminUser,
  } = req.body;

  // Check required fields including stripeCustomerId
  const requiredFields = [
    "editorId",
    "firstName",
    "lastName",
    "username",
    "email",
    "address",
    "phone",
    "stripeCustomerId",
    "endUserCanEdit",
    "adminUser",
  ];
  if (requiredFields.some((field) => !req.body[field])) {
    console.warn("Missing required fields!", {
      firstName,
      lastName,
      email,
      address,
    });
    return res.status(400).json({ message: "Missing required fields!" });
  }
  const canEndUserEdit = JSON.parse(req.body.endUserCanEdit.toLowerCase())
    ? 1
    : 0;
  const isAdminUser = JSON.parse(req.body.adminUser.toLowerCase()) ? 1 : 0;
  const userId = req.user?.id; // Safely access user ID
  if (!userId) {
    console.error("User ID not found in request.");
    return res.status(401).json({ message: "Unauthorized: User ID not found" });
  }
  const admin = await checkAdminStatusByID(userId); //gpt is this the way to access the variable from the user in the request?
  const reqOwner = await checkOwnerStatusByID(userId);
  const owner = await checkOwnerStatusByID(editorId);
  const editorAdmin = await checkAdminStatusByID(editorId);
  if (!admin && userId !== editorId) {
    return res.status(400).json({
      error:
        "USER IS NOT AN APPROVED ADMIN OF LONE WOLF IT & THEY ARE *trying* to EDIT SOMEONE ELSES ACCOUNT...",
    });
  }
  if (owner) {
    return res
      .status(400)
      .json({ error: "OWNER ACCOUNT CANNOT BE MODIFIED..." });
  }
  if (editorAdmin && !reqOwner) {
    return res
      .status(400)
      .json({ error: "Admin cannot edit an admin account..." });
  }
  if (isAdminUser && !editorAdmin && !reqOwner) {
    return res
      .status(400)
      .json({ error: "Only owner accounts can make someone an admin..." });
  }
  if (!allowedUsername(username)) {
    return res.status(400).json({
      error:
        "Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed.",
    });
  }
  try {
    // Update user information in the database
    await new Promise((resolve, reject) => {
      //GPT fix this query to update the user with the given editorId
      db.run(
        `UPDATE users SET first_name = ?, middle_name = ?, last_name = ?, username = ?, phone = ?, address = ?, profile_photo = ?, stripeCustomerId = ?, dbaName = ?, businessAddress = ?, endUserCanEdit = ?, adminUser = ?, owner = ? WHERE id = ?`,
        [
          firstName,
          middleName,
          lastName,
          username,
          phone,
          address,
          null,
          stripeCustomerId,
          dbaName,
          businessAddress,
          canEndUserEdit,
          isAdminUser,
          owner,
          editorId,
        ],
        function (err) {
          if (err) {
            console.error("Error updating user:", err.message);
            return reject(err);
          }
          resolve(this); // Resolve with the current context
        }
      );
    });

    console.log("User updated successfully:", { editorId, ...req.body });
    res.status(200).json({ message: "User updated successfully!" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: "Error updating user: " + error.message });
  }
});

app.put("/api/auth/edit-user", authenticateJWT, async (req, res) => {
  const {
    firstName,
    middleName,
    lastName,
    phone,
    address,
    username,
    email,
    stripeCustomerId,
    dbaName,
    businessAddress,
  } = req.body;

  // Check required fields including stripeCustomerId
  const requiredFields = [
    "firstName",
    "lastName",
    "username",
    "email",
    "address",
    "phone",
    "stripeCustomerId",
    "dbaName",
    "businessAddress",
  ];
  if (requiredFields.some((field) => !req.body[field])) {
    console.warn("Missing required fields!", {
      firstName,
      lastName,
      email,
      address,
    });
    return res.status(400).json({ message: "Missing required fields!" });
  }

  const userId = req.user?.id; // Safely access user ID
  if (!userId) {
    console.error("User ID not found in request.");
    return res.status(401).json({ message: "Unauthorized: User ID not found" });
  }

  // Check if user is allowed to edit
  const userRow = await new Promise((resolve, reject) => {
    db.get(
      "SELECT endUserCanEdit FROM users WHERE id = ?",
      [userId],
      (err, row) => {
        if (err) return reject(err);
        resolve(row);
      }
    );
  });
  if (
    !userRow ||
    userRow.endUserCanEdit === 0 ||
    userRow.endUserCanEdit === false
  ) {
    return res
      .status(403)
      .json({ message: "You are not allowed to edit your information." });
  }

  if (!allowedUsername(username)) {
    return res.status(400).json({
      error:
        "Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed.",
    });
  }

  let adminUser = await checkAdminStatus(email); //gpt is this the way to access the variable from the user in the request?
  const owner = await checkOwnerStatusByID(userId);
  try {
    // Update user information in the database
    await new Promise((resolve, reject) => {
      db.run(
        `UPDATE users SET first_name = ?, middle_name = ?, last_name = ?, username = ?, phone = ?, address = ?, profile_photo = ?, stripeCustomerId = ?, dbaName = ?, businessAddress = ?, endUserCanEdit = ?, adminUser = ?, owner = ? WHERE id = ?`,
        [
          firstName,
          middleName,
          lastName,
          username,
          phone,
          address,
          null,
          stripeCustomerId,
          dbaName,
          businessAddress,
          true,
          adminUser,
          owner,
          userId,
        ],
        function (err) {
          if (err) {
            console.error("Error updating user:", err.message);
            return reject(err);
          }
          resolve(this); // Resolve with the current context
        }
      );
    });

    console.log("User updated successfully:", { userId, ...req.body });
    res.status(200).json({ message: "User updated successfully!" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: "Error updating user: " + error.message });
  }
});

app.post(
  "/api/auth/update-stripe-customer",
  authenticateJWT,
  async (req, res) => {
    const {
      username,
      firstName,
      lastName,
      phone,
      email,
      address,
      dbaName,
      businessAddress,
    } = req.body;

    // Confirm the address object is structured correctly
    const stripeAddress = {
      line1: address.line1 || "",
      line2: address.line2 || "", // Optional can be empty
      city: address.city || "",
      state: address.state || "",
      postal_code: address.postal_code || "",
      country: address.country || "",
    };

    // Get the userId from the request, which is populated by the authenticateJWT middleware
    const userId = req.user.id;

    // Check if user is allowed to edit
    db.get(
      "SELECT endUserCanEdit, stripeCustomerId, username FROM users WHERE id = ?",
      [userId],
      async (err, row) => {
        if (err) {
          console.error("Error fetching user:", err);
          return res.status(500).json({
            message: "Server error while fetching user: " + err.message,
          });
        }
        if (!row || row.endUserCanEdit === 0 || row.endUserCanEdit === false) {
          return res.status(403).json({
            message: "You are not allowed to edit your Stripe information.",
          });
        }

        // Ensure that we correctly access the stripeCustomerId and username
        const customerId = row ? row.stripeCustomerId : null;

        // Validate that customerId is present
        if (!customerId) {
          console.warn("Missing Stripe customer ID for user ID:", userId);
          return res
            .status(400)
            .json({ message: "No Stripe customer ID found." });
        }

        let adminUser = await checkAdminStatus(email);

        if (!allowedUsername(username)) {
          return res.status(400).json({
            error:
              "Cannot update stripe customer. Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed.",
          });
        }

        // Log the customerId and username before making the Stripe request
        console.log(`Updating Stripe customer with ID: ${customerId}`);
        console.log(`Updating Stripe customer username to: ${username}`);

        // Update the Stripe customer details
        try {
          // Build metadata, ensuring all values are strings and filtering out undefined/null
          const rawMetadata = {
            username,
            dbaName,
            businessAddress,
            endUserCanEdit: String(true),
            adminUser:
              adminUser !== undefined && adminUser !== null
                ? String(adminUser)
                : String(false),
          };
          const metadata = Object.fromEntries(
            Object.entries(rawMetadata).filter(
              ([_, v]) => v !== undefined && v !== null
            )
          );
          const updatedCustomer = await stripe.customers.update(customerId, {
            name: `${firstName} ${lastName}`,
            phone: phone,
            address: stripeAddress, // Use the structured address object here
            metadata,
          });

          console.log("Stripe customer updated successfully:", updatedCustomer); // Log response
          return res
            .status(200)
            .json({ message: "Stripe customer updated successfully." });
        } catch (error) {
          console.error("Error updating Stripe customer:", error);
          return res.status(500).json({
            message: "Failed to update Stripe customer: " + error.message,
          });
        }
      }
    );
  }
);

app.post(
  "/api/admin/update-stripe-customer",
  authenticateJWT,
  async (req, res) => {
    try {
      // Pull stripeCustomerData out of the body
      const { stripeCustomerData = {} } = req.body;

      // Then destructure the actual customer fields
      const {
        stripeCustomerId = "",
        firstName = "",
        lastName = "",
        phone = "",
        email = "",
        address, // may be string or object
        username = "",
        dbaName = "",
        businessAddress = "",
        endUserCanEdit,
        adminUser,
      } = stripeCustomerData;

      if (!stripeCustomerId) {
        return res
          .status(400)
          .json({ message: "stripeCustomerId is required." });
      }

      // Admin‐check as you already have it
      const adminId = req.user.id;
      if (!(await checkAdminStatusByID(adminId))) {
        return res.status(403).json({ message: "Not an approved admin." });
      }

      if (!allowedUsername(username)) {
        return res.status(400).json({
          message:
            "Cannot update stripe customer. Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed.",
        });
      }

      //
      // ── PARSE ADDRESS HERE ────────────────────────────────────────────────────────
      //
      let stripeAddress = {};

      if (typeof address === "string") {
        // split on commas and trim whitespace
        const parts = address.split(",").map((s) => s.trim());

        stripeAddress = {
          line1: parts[0] || "",
          line2: parts[1] || "",
          city: parts[2] || "",
          state: parts[3] || "",
          postal_code: parts[4] || "",
          country: parts[5] || "",
        };
      } else if (typeof address === "object" && address !== null) {
        // if you ever send a structured object instead
        stripeAddress = {
          line1: address.line1 || "",
          line2: address.line2 || "",
          city: address.city || "",
          state: address.state || "",
          postal_code: address.postal_code || "",
          country: address.country || "",
        };
      } else {
        // fallback: shove the entire thing in line1
        stripeAddress = { line1: String(address || "") };
      }

      //
      // ── BUILD YOUR UPDATE PARAMS ───────────────────────────────────────────────────
      //

      // Build metadata, ensuring all values are strings and filtering out undefined/null
      const rawMetadata = {
        username,
        dbaName,
        businessAddress,
        updatedByAdminId: String(adminId),
        endUserCanEdit:
          endUserCanEdit !== undefined && endUserCanEdit !== null
            ? String(endUserCanEdit)
            : String(false),
        adminUser:
          adminUser !== undefined && adminUser !== null
            ? String(adminUser)
            : String(false),
      };
      // Remove undefined/null values
      const metadata = Object.fromEntries(
        Object.entries(rawMetadata).filter(
          ([_, v]) => v !== undefined && v !== null
        )
      );

      const updateParams = {
        name: `${firstName} ${lastName}`.trim() || undefined,
        email: email || undefined, // must pass email if you want to update it
        phone: phone || undefined,
        address: stripeAddress,
        metadata,
      };

      console.log(
        `Admin(${adminId}) → updating ${stripeCustomerId} with:`,
        updateParams
      );

      const updatedCustomer = await stripe.customers.update(
        stripeCustomerId,
        updateParams
      );

      return res.status(200).json({
        message: "Stripe customer updated.",
        customer: updatedCustomer.id,
      });
    } catch (err) {
      console.error("Error updating Stripe customer:", err);
      return res.status(500).json({
        message: "Failed to update Stripe customer: " + err.message,
      });
    }
  }
);

// Endpoint to send verification code
app.post("/api/auth/send-verification-code", (req, res) => {
  const { email } = req.body;

  // Validate that the email field is present
  if (!email) {
    return res.status(400).send("Email is required.");
  }

  // Check if the email exists in the database
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) {
      console.error("Database error while checking email:", err);
      return res.status(500).send("Server error while checking email.");
    }

    if (!user) {
      // If user not found in the database
      return res.status(404).send("Email does not exist in our records.");
    }

    // Check if the account is a Google account
    if (user.google_id) {
      // Redirect to Google authentication endpoint
      return res.status(500).send("Email already exists as a Google Account."); // Redirect to Google authentication
    }

    // Generate a random verification code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    // Store the verification code temporarily
    verificationCodes[email] = verificationCode;

    setVerificationCodeExpiry(email);

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Verification Code for Password Reset",
      text: `Your verification code is ${verificationCode}`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res
          .status(500)
          .send("Error sending verification email: " + error.message);
      }
      console.log("Verification code sent to:", email);
      res.status(200).send("Verification code sent to email.");
    });
  });
});
let tempStripeUsers = {}; // Global variable to store temp Stripe users

// Function to fetch state data for all countries
async function fetchStateData() {
  // Use ISO_3166_PATH from environment variables, fallback to default if not set
  const filePath = process.env.ISO_3166_PATH;

  try {
    // Read the file synchronously
    const data = fs.readFileSync(filePath, "utf8"); // Reading the JSON file as a string

    // Parse the JSON string into an object
    const jsonData = JSON.parse(data);

    // Create a mapping to store all states for all countries
    const allStatesMapping = {};

    // Iterate over each country in the JSON data
    for (const [country, details] of Object.entries(jsonData)) {
      if (details.divisions) {
        // Map each division under the country
        Object.entries(details.divisions).forEach(([code, name]) => {
          allStatesMapping[code] = name; // e.g., US-IL -> "Illinois"
        });
      } else {
        console.warn(`No divisions found for country: ${country}.`);
      }
    }

    //console.log('All States Mapping:', allStatesMapping); // Log for verification
    return allStatesMapping; // Return the complete mapping of all states for all countries
  } catch (error) {
    console.error("Error fetching state data from file:", error);
    return {};
  }
}

// Function to format address as a string for the database
function formatAddressForDatabase(address) {
  const {
    line1,
    line2 = "", // Default to an empty string for line2
    city = "",
    state = "",
    postal_code = "",
    country = "",
  } = address;

  const formattedAddress = [line1, line2, city, state, postal_code, country]
    .join(", ")
    .replace(/,\s*,/g, ", ,");

  return formattedAddress.trim();
}
// Assuming `db` is your SQLite database instance:

const dbGet = promisify(db.get.bind(db));
const dbRun = promisify(db.run.bind(db));

async function syncStripeCustomers(stateMapping) {
  let hasMore = true;
  let startingAfter = ""; // For pagination

  try {
    while (hasMore) {
      let customers;

      // Fetch customers from Stripe
      if (startingAfter !== "") {
        customers = await stripe.customers.list({
          limit: 100,
          starting_after: startingAfter,
        });
      } else {
        customers = await stripe.customers.list({ limit: 100 });
      }

      if (!customers.data.length) {
        hasMore = false; // No data means we can break the loop
        break;
      }

      await Promise.all(
        customers.data.map(async (customer) => {
          const {
            id: stripeCustomerID,
            email,
            phone,
            address,
            metadata,
          } = customer;

          try {
            // Check if the customer already exists in the database
            const user = await dbGet("SELECT * FROM users WHERE email = ?", [
              email,
            ]);

            if (user) {
              // Handle the address state mapping
              if (address && address.state) {
                const stateKey = `${address.country}-${address.state}`; // Constructing the key, e.g., US-IL
                if (stateMapping[stateKey]) {
                  address.state = stateMapping[stateKey];
                  console.log(`Mapped ${stateKey} to ${address.state}`);
                }
              } else {
                console.warn(
                  "Address or state is not defined for customer:",
                  customer
                );
              }

              const formattedAddress = formatAddressForDatabase(address);
              const firstName = customer.name.split(" ")[0] || "";
              const middleName =
                customer.name.split(" ").slice(1, -1).join(" ") || "";
              const lastName = customer.name.split(" ").pop() || "";
              const dbaName = metadata.dbaName || null;
              const businessAddress = metadata.businessAddress || null;
              const endUserCanEdit =
                metadata.endUserCanEdit === "true" ||
                metadata.endUserCanEdit === "1";
              const adminUser =
                metadata.adminUser === "true" || metadata.adminUser === "1";

              await dbRun(
                `UPDATE users SET 
			  first_name = ?, 
			  middle_name = ?, 
			  last_name = ?, 
			  phone = ?, 
			  address = ?,
			  username = ?, 
			  profile_photo = ?,
			  stripeCustomerID = ?,
			  dbaName = ?, 
			  businessAddress = ?,
			  endUserCanEdit = ?,
			  adminUser = ?
			  WHERE email = ?`,
                [
                  firstName,
                  middleName,
                  lastName,
                  phone,
                  formattedAddress,
                  user.username,
                  null,
                  stripeCustomerID,
                  dbaName,
                  businessAddress,
                  endUserCanEdit,
                  adminUser,
                  email,
                ]
              );

              console.log(
                `Updated user: ${email} with State: ${address.state}`
              );
            }
          } catch (dbError) {
            console.error(
              "Database error during processing customer:",
              dbError
            );
          }
        })
      );

      hasMore = customers.has_more; // Update pagination flag
      startingAfter = customers.data[customers.data.length - 1].id;
    }
  } catch (error) {
    console.error("Error syncing Stripe customers:", error);
  }
}
// Function to initiate syncing process periodically
async function initiateStripeSync() {
  try {
    const stateMapping = await fetchStateData();
    await syncStripeCustomers(stateMapping);
  } catch (error) {
    console.error("Error during stripe syncing process:", error);
  }
}
setInterval(initiateStripeSync, 20000000); // Adjust sync frequency as necessary

app.post("/api/sync-customers", authenticateJWT, async (req, res) => {
  const stateMapping = await fetchStateData(); // Expected state mapping from request body
  const userId = req.user.id;

  if (!stateMapping) {
    return res
      .status(400)
      .send({ error: "State mapping failed to be fetched..." });
  }

  const admin = await checkAdminStatusByID(userId);
  if (!admin) {
    return res
      .status(400)
      .send({ error: "USER IS NOT AN APPROVED ADMIN OF LONE WOLF IT..." });
  }

  try {
    await syncStripeCustomers(stateMapping);
    return res
      .status(200)
      .send({ message: "Sync to database completed successfully" });
  } catch (error) {
    console.error("Error during sync:", error);
    return res.status(500).send({
      error: "An error occurred during sync to database: " + error.message,
    });
  }
});
app.post(
  "/api/cleanup-deleted-user-content",
  authenticateJWT,
  async (req, res) => {
    const userId = req.user.id;

    const admin = await checkAdminStatusByID(userId);
    if (!admin) {
      return res
        .status(400)
        .send({ error: "USER IS NOT AN APPROVED ADMIN OF LONE WOLF IT..." });
    }

    try {
      await cleanupDeletedUserContent();
      return res
        .status(200)
        .send({ message: "Cleanup completed successfully..." });
    } catch (error) {
      console.error("Error during sync:", error);
      return res.status(500).send({
        error: "An error occurred during the cleanup of the database...",
      });
    }
  }
);
async function cleanupDeletedUserContent() {
  // Get a list of all existing user IDs
  db.all(`SELECT id FROM users`, [], (err, rows) => {
    if (err) {
      console.error("Error fetching users:", err.message);
      return;
    }

    // Extract existing user IDs from the result
    const existingUserIds = new Set(rows.map((row) => row.id));

    // Delete testimonials for non-existing users
    db.run(
      `DELETE FROM testimonials WHERE user_id NOT IN (${Array.from(
        existingUserIds
      ).join(",")})`,
      (err) => {
        if (err) {
          console.error(
            "Error deleting testimonials for deleted users:",
            err.message
          );
        } else {
          console.log("Deleted testimonials for users that no longer exist.");
        }
      }
    );
  });
}
// GET '/api/testimonials'
app.get("/api/testimonials", authenticateJWT, (req, res) => {
  const { approvedTestimonials } = req.query;

  const userId = req.user.id;

  // Initialize a variable for admin user status
  let adminUser = false;

  // Query to check if the user is an admin
  db.get(
    "SELECT adminUser FROM users WHERE id = ?",
    [userId],
    async (err, user) => {
      if (err) {
        // Handle the error: send a 500 status response with an error message
        return res
          .status(500)
          .json({ message: "Error checking user permissions: " + err.message });
      }

      // Check if the user object is found and if the user is an admin
      if (user && user.adminUser) {
        adminUser = true;
      }

      // Determine whether to filter approved testimonials based on the query parameter
      let approved = true; // Default to true
      if (
        typeof approvedTestimonials === "undefined" ||
        approvedTestimonials === "1" ||
        approvedTestimonials === "true"
      ) {
        approved = true;
      } else if (adminUser) {
        approved = false;
      }

      if (
        typeof approvedTestimonials !== "undefined" &&
        (approvedTestimonials === "0" || approvedTestimonials === "false") &&
        !adminUser
      ) {
        return res.status(403).json({
          message:
            "You do not have permission to view unapproved testimonials...",
        });
      }

      // Query to retrieve testimonials based on the approved status
      db.all(
        "SELECT * FROM testimonials WHERE approved = ?",
        [approved],
        (err, rows) => {
          if (err) {
            return res.status(500).json({
              message: "Error retrieving testimonials: " + err.message,
            });
          }
          res.json(rows);
        }
      );
    }
  );
});
app.get("/api/testimonials/approved", (req, res) => {
  // Query to retrieve all approved testimonials
  db.all(
    "SELECT * FROM testimonials WHERE approved = ?",
    [true],
    (err, rows) => {
      if (err) {
        console.error("Error retrieving approved testimonials:", err);
        return res.status(500).json({
          message: "Error retrieving approved testimonials: " + err.message,
        });
      }
      res.json(rows);
    }
  );
});
app.get("/api/users/testimonials", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT * FROM testimonials WHERE user_id = ?",
    [userId],
    (err, rows) => {
      if (err) {
        console.error("Error retrieving user testimonials:", err);
        return res.status(500).json({
          message: "Error retrieving user testimonials: " + err.message,
        });
      }
      res.json(rows);
    }
  );
});
// POST '/api/submit-testimonial'
app.post("/api/submit-testimonial", authenticateJWT, async (req, res) => {
  const { testimonial, turnstileToken } = req.body; // Assuming you have a testimonial field
  const userId = req.user.id; // Extract user ID from JWT

  if (!testimonial) {
    return res.status(400).json({ message: "Testimonial is required" });
  }
  if (testimonial.length > 250) {
    return res
      .status(400)
      .json({ message: "Testimonial cannot exceed 250 characters..." });
  }
  // Require Turnstile token
  if (!turnstileToken && process.env.TURNSTILES_ENABLED === "true") {
    return res.status(400).json({ message: "Missing captcha token." });
  }

  // Verify Turnstile token with Cloudflare
  if (process.env.TURNSTILES_ENABLED === "true") {
    try {
      const verifyUrl =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";
      const params = new URLSearchParams();
      params.append("secret", process.env.TURNSTILE_SECRET);
      params.append("response", turnstileToken);
      // optional: params.append("remoteip", req.ip);

      const verifyRes = await fetch(verifyUrl, {
        method: "POST",
        body: params,
      });
      const verifyJson = await verifyRes.json();
      if (!verifyJson.success) {
        console.warn("Turnstile verify failed:", verifyJson);
        return res.status(403).json({ message: "Captcha verification failed." });
      }
    } catch (err) {
      console.error("Turnstile verification error:", err);
      return res.status(500).json({ message: "Captcha verification error: " + err.message });
    }
  }

  console.log("User requested a testimonial submittal");
  db.run(
    "INSERT INTO testimonials (user_id, testimonial, approved) VALUES (?, ?, ?)",
    [userId, testimonial, false],
    function (err) {
      if (err) {
        return res
          .status(500)
          .json({ message: "Error submitting testimonial: " + err.message });
      }
      res.status(201).json({
        message: "Testimonial submitted for approval",
        id: this.lastID,
      });
    }
  );
});

// POST '/api/approve-testimonial'
app.post("/api/approve-testimonial", authenticateJWT, (req, res) => {
  const { testimonialId } = req.body; // Assuming you have a testimonialId field
  const userId = req.user.id; // Extract user ID from JWT

  console.log(
    `User ID: ${userId} is attempting to approve testimonial ID: ${testimonialId}`
  );

  // Check if the user is an admin by querying the database
  db.get("SELECT adminUser FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) {
      console.error("Error fetching user from database:", err);
      return res
        .status(500)
        .json({ message: "Error checking user permissions: " + err.message });
    }

    // Check if the user is found and is an admin
    if (!user || !user.adminUser) {
      console.log(`User ID: ${userId} is not an admin.`);
      return res.status(403).json({
        message: "You do not have permission to approve testimonials",
      });
    }

    // Proceed to update the testimonial status
    db.run(
      "UPDATE testimonials SET approved = ? WHERE id = ?",
      [true, testimonialId],
      function (err) {
        if (err) {
          console.error("Error approving testimonial:", err);
          return res
            .status(500)
            .json({ message: "Error approving testimonial: " + err.message });
        }
        if (this.changes === 0) {
          console.log(`Testimonial ID: ${testimonialId} not found.`);
          return res.status(404).json({ message: "Testimonial not found" });
        }
        console.log(
          `Testimonial ID: ${testimonialId} has been approved by User ID: ${userId}.`
        );
        res.json({ message: "Testimonial approved" });
      }
    );
  });
});

// POST '/api/edit-testimonial'
app.post("/api/edit-testimonial", authenticateJWT, (req, res) => {
  const { testimonialId, updatedTestimonial } = req.body; // Expect testimonialId and updatedTestimonial in the request body
  const user_id = req.user.id; // Extract user ID from JWT

  console.log(
    `User ID: ${user_id} is attempting to edit testimonial ID: ${testimonialId}`
  );

  // Get the original creator of the testimonial
  db.get(
    "SELECT user_id, approved FROM testimonials WHERE id = ?",
    [testimonialId],
    (err, testimonial) => {
      if (err) {
        console.error("Error fetching testimonial from database:", err);
        return res
          .status(500)
          .json({ message: "Error retrieving testimonial: " + err.message });
      }

      if (!testimonial) {
        console.log(`Testimonial ID: ${testimonialId} not found.`);
        return res.status(404).json({ message: "Testimonial not found" });
      }
      if (updatedTestimonial.length > 250) {
        return res
          .status(400)
          .json({ message: "Testimonial cannot exceed 250 characters..." });
      }
      // Check if the user is an admin by querying the database
      db.get(
        "SELECT adminUser FROM users WHERE id = ?",
        [user_id],
        (err, user) => {
          if (err) {
            console.error("Error fetching user from database:", err);
            return res.status(500).json({
              message: "Error checking user permissions: " + err.message,
            });
          }

          // Check if the user is found and is an admin or the original creator of the testimonial
          const isAdmin = user?.adminUser ?? false;
          const isOriginalUser = testimonial.user_id === user_id; // This checks if the user is the original creator

          if (!isAdmin && !isOriginalUser) {
            console.log(
              `User ID: ${user_id} does not have permission to edit the testimonial.`
            );
            return res.status(403).json({
              message: "You do not have permission to edit testimonials",
            });
          }

          // Update the testimonial only if it's not approved
          /**if (testimonial.approved) {
		console.log(`Testimonial ID: ${testimonialId} is already approved and cannot be edited.`);
		return res.status(403).json({ message: 'Approved testimonials cannot be edited' });
	  }*/

          db.run(
            "UPDATE testimonials SET testimonial = ? WHERE id = ?",
            [updatedTestimonial, testimonialId],
            function (err) {
              if (err) {
                console.error("Error updating testimonial:", err);
                return res.status(500).json({
                  message: "Error updating testimonial: " + err.message,
                });
              }
              if (this.changes === 0) {
                console.log(
                  `No changes were made to Testimonial ID: ${testimonialId}.`
                );
                return res
                  .status(404)
                  .json({ message: "Testimonial not found or already edited" });
              }
              console.log(
                `Testimonial ID: ${testimonialId} has been updated successfully by User ID: ${user_id}.`
              );
              res.json({ message: "Testimonial updated successfully" });
            }
          );
        }
      );
    }
  );
});

// DELETE '/api/delete-testimonial'
app.delete("/api/delete-testimonial", authenticateJWT, (req, res) => {
  const { testimonialId } = req.body; // Expect testimonialId in the request body
  const user_id = req.user.id; // Extract user ID from JWT

  console.log(
    `User ID: ${user_id} is attempting to delete testimonial ID: ${testimonialId}`
  );

  // Get the original creator of the testimonial
  db.get(
    "SELECT user_id FROM testimonials WHERE id = ?",
    [testimonialId],
    (err, testimonial) => {
      if (err) {
        console.error("Error fetching testimonial from database:", err);
        return res
          .status(500)
          .json({ message: "Error retrieving testimonial: " + err.message });
      }

      if (!testimonial) {
        console.log(`Testimonial ID: ${testimonialId} not found.`);
        return res.status(404).json({ message: "Testimonial not found" });
      }
      // Check if the user is an admin by querying the database
      db.get(
        "SELECT adminUser FROM users WHERE id = ?",
        [user_id],
        (err, user) => {
          if (err) {
            console.error("Error fetching user from database:", err);
            return res.status(500).json({
              message: "Error checking user permissions: " + err.message,
            });
          }
          // Check if the user is found and is an admin or the original creator of the testimonial
          const isAdmin = user?.adminUser ?? false;
          const isOriginalUser = testimonial.user_id === user_id;

          if (!isAdmin && !isOriginalUser) {
            console.log(
              `User ID: ${user_id} does not have permission to delete the testimonial.`
            );
            return res.status(403).json({
              message: "You do not have permission to delete testimonials",
            });
          }

          // Proceed to delete the testimonial
          db.run(
            "DELETE FROM testimonials WHERE id = ?",
            [testimonialId],
            function (err) {
              if (err) {
                console.error("Error deleting testimonial:", err);
                return res.status(500).json({
                  message: "Error deleting testimonial: " + err.message,
                });
              }
              if (this.changes === 0) {
                console.log(
                  `No changes were made, testimonial ID: ${testimonialId} may not exist.`
                );
                return res
                  .status(404)
                  .json({ message: "Testimonial not found" });
              }
              console.log(
                `Testimonial ID: ${testimonialId} has been deleted successfully by User ID: ${user_id}.`
              );
              res.json({ message: "Testimonial deleted successfully" });
            }
          );
        }
      );
    }
  );
});
app.delete("/api/user/delete-testimonial", authenticateJWT, (req, res) => {
  const { testimonialId } = req.body; // Expect testimonialId in the request body
  const user_id = req.user.id; // Extract user ID from JWT

  console.log(
    `User ID: ${user_id} is attempting to delete testimonial ID: ${testimonialId}`
  );

  // Get the original creator of the testimonial
  db.get(
    "SELECT user_id FROM testimonials WHERE id = ?",
    [testimonialId],
    (err, testimonial) => {
      if (err) {
        console.error("Error fetching testimonial from database:", err);
        return res
          .status(500)
          .json({ message: "Error retrieving testimonial: " + err.message });
      }

      if (!testimonial) {
        console.log(`Testimonial ID: ${testimonialId} not found.`);
        return res.status(404).json({ message: "Testimonial not found" });
      }

      // Only allow the original user to delete their testimonial
      const isOriginalUser = testimonial.user_id === user_id;

      if (!isOriginalUser) {
        console.log(
          `User ID: ${user_id} does not have permission to delete the testimonial.`
        );
        return res.status(403).json({
          message: "You do not have permission to delete this testimonial",
        });
      }

      // Proceed to delete the testimonial
      db.run(
        "DELETE FROM testimonials WHERE id = ?",
        [testimonialId],
        function (err) {
          if (err) {
            console.error("Error deleting testimonial:", err);
            return res
              .status(500)
              .json({ message: "Error deleting testimonial: " + err.message });
          }
          if (this.changes === 0) {
            console.log(
              `No changes were made, testimonial ID: ${testimonialId} may not exist.`
            );
            return res.status(404).json({ message: "Testimonial not found" });
          }
          console.log(
            `Testimonial ID: ${testimonialId} has been deleted successfully by User ID: ${user_id}.`
          );
          res.json({ message: "Testimonial deleted successfully" });
        }
      );
    }
  );
});
app.put("/api/user/edit-user-preference", authenticateJWT, async (req, res) => {
  const { preference_key, preference_value } = req.body; // Extract necessary fields
  const user_id = req.user.id; // Extract user ID from JWT

  // SQL query to update user preference
  const query = `UPDATE user_preferences SET preference_value = ? WHERE user_id = ? AND preference_key = ?`;

  db.run(query, [preference_value, user_id, preference_key], function (err) {
    if (err) {
      console.error("Error updating user preference:", err.message);
      return res.status(500).send({
        error:
          "An error occurred while updating user preference: " + err.message,
      });
    }

    if (this.changes === 0) {
      console.log(
        `No updates made for user ID: ${user_id} and preference key: ${preference_key} (not found or no change).`
      );
      return res.status(404).send({ error: "User preference not found." });
    }

    //console.log(
    //  `User ID: ${user_id} successfully edited preference key: ${preference_key}.`
    //);
    return res
      .status(200)
      .send({ message: "User preference edited successfully." });
  });
});

app.get("/api/user/preferences", authenticateJWT, async (req, res) => {
  const user_id = req.user.id; // Extract user ID from JWT
  console.log(`GET /api/user/preferences invoked by user ID: ${user_id}`);
  // SQL query to retrieve user preferences
  const query = `SELECT preference_key, preference_value FROM user_preferences WHERE user_id = ?`;

  db.all(query, [user_id], (err, rows) => {
    if (err) {
      console.error("Error retrieving user preferences:", err.message);
      return res.status(500).send({
        error:
          "An error occurred while retrieving user preferences: " + err.message,
      });
    }

    console.log(`User ID: ${user_id} retrieved preferences successfully.`);
    return res.status(200).send({ preferences: rows });
  });
});

app.post("/api/user/create-preference", authenticateJWT, (req, res) => {
  const { preference_key, preference_value } = req.body; // Extract necessary fields
  const user_id = req.user.id; // Extract user ID from JWT
  console.log(
    `POST /api/user/create-preference invoked by user ID: ${user_id}`
  );
  // Validate that the required fields are present
  if (!preference_key || !preference_value) {
    return res
      .status(400)
      .send({ error: "Preference key and value are required." });
  }

  // First, check if the preference already exists for this user
  const checkQuery = `SELECT 1 FROM user_preferences WHERE user_id = ? AND preference_key = ?`;
  db.get(checkQuery, [user_id, preference_key], (err, row) => {
    if (err) {
      console.error("Error checking existing user preference:", err.message);
      return res.status(500).send({
        error:
          "An error occurred while checking user preference: " + err.message,
      });
    }
    if (row) {
      // Preference already exists
      console.log(
        `Preference key: ${preference_key} already exists for user ID: ${user_id}.`
      );
      return res
        .status(409)
        .send({ error: "Preference already exists for this user." });
    }

    // SQL query to insert a new user preference
    const insertQuery = `INSERT INTO user_preferences (user_id, preference_key, preference_value) VALUES (?, ?, ?)`;
    db.run(
      insertQuery,
      [user_id, preference_key, preference_value],
      function (err) {
        if (err) {
          console.error("Error creating user preference:", err.message);
          return res.status(500).send({
            error:
              "An error occurred while creating user preference: " +
              err.message,
          });
        }

        console.log(
          `User ID: ${user_id} created preference key: ${preference_key} successfully.`
        );
        return res.status(201).send({
          message: "User preference created successfully.",
          id: this.lastID,
        });
      }
    );
  });
});

app.delete("/api/user/delete-preference", authenticateJWT, (req, res) => {
  const { preference_key } = req.body; // Expect preference_key in the request body
  const user_id = req.user.id; // Extract user ID from JWT
  console.log(
    `User ID: ${user_id} is attempting to delete preference key: ${preference_key}`
  );
  // SQL query to delete user preference
  const query = `DELETE FROM user_preferences WHERE user_id = ? AND preference_key = ?`;
  db.run(query, [user_id, preference_key], function (err) {
    if (err) {
      console.error("Error deleting user preference:", err.message);
      return res.status(500).send({
        error:
          "An error occurred while deleting user preference: " + err.message,
      });
    }

    if (this.changes === 0) {
      console.log(
        `No preference found for user ID: ${user_id} and preference key: ${preference_key}.`
      );
      return res.status(404).send({ error: "User preference not found." });
    }

    console.log(
      `User ID: ${user_id} deleted preference key: ${preference_key} successfully.`
    );
    return res
      .status(200)
      .send({ message: "User preference deleted successfully." });
  });
});

app.get("/api/user/get-preference", authenticateJWT, (req, res) => {
  const { preference_key } = req.query; // Expect preference_key in the query parameters
  const user_id = req.user.id; // Extract user ID from JWT
  //console.log(
  //  `User ID: ${user_id} is attempting to retrieve preference key: ${preference_key}`
  //);
  // SQL query to retrieve user preference
  const query = `SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = ?`;
  db.get(query, [user_id, preference_key], (err, row) => {
    if (err) {
      console.error("Error retrieving user preference:", err.message);
      return res.status(500).send({
        error:
          "An error occurred while retrieving user preference: " + err.message,
      });
    }

    if (!row) {
      console.log(
        `No preference found for user ID: ${user_id} and preference key: ${preference_key}.`
      );
      return res.status(404).send({ error: "User preference not found." });
    }

    //console.log(
    //  `User ID: ${user_id} retrieved preference key: ${preference_key} successfully.`
    //);
    return res.status(200).send({ preference_value: row.preference_value });
  });
});

app.get("/api/admin/contact-form/submissions", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  // Check if the user is an admin
  db.get("SELECT adminUser FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) {
      console.error("Error checking user permissions:", err);
      return res
        .status(500)
        .send("Server error while checking permissions: " + err.message);
    }

    if (!user || !user.adminUser) {
      return res
        .status(403)
        .send("You do not have permission to access this resource.");
    }

    // Fetch contact form submissions
    db.all("SELECT * FROM contact_form_submissions", [], (err, rows) => {
      if (err) {
        console.error("Error fetching contact form submissions:", err);
        return res
          .status(500)
          .send("Server error while fetching submissions: " + err.message);
      }
      res.json(rows);
    });
  });
});

app.get(
  "/api/admin/contact-form/submission/:id",
  authenticateJWT,
  (req, res) => {
    const submissionId = req.params.id;
    const userId = req.user.id;
    // Check if the user is an admin
    db.get(
      "SELECT adminUser FROM users WHERE id = ?",
      [userId],
      (err, user) => {
        if (err) {
          console.error("Error checking user permissions:", err);
          return res
            .status(500)
            .send("Server error while checking permissions: " + err.message);
        }

        if (!user || !user.adminUser) {
          return res
            .status(403)
            .send("You do not have permission to access this resource.");
        }

        // Fetch the contact form submission
        db.get(
          "SELECT * FROM contact_form_submissions WHERE id = ?",
          [submissionId],
          (err, row) => {
            if (err) {
              console.error("Error fetching contact form submission:", err);
              return res
                .status(500)
                .send("Server error while fetching submission: " + err.message);
            }
            if (!row) {
              return res.status(404).send("Submission not found.");
            }
            res.json(row);
          }
        );
      }
    );
  }
);

app.delete(
  "/api/admin/contact-form/submission/:id",
  authenticateJWT,
  (req, res) => {
    const submissionId = req.params.id;
    const userId = req.user.id;

    // Check if the user is an admin
    db.get(
      "SELECT adminUser FROM users WHERE id = ?",
      [userId],
      (err, user) => {
        if (err) {
          console.error("Error checking user permissions:", err);
          return res
            .status(500)
            .send("Server error while checking permissions: " + err.message);
        }

        if (!user || !user.adminUser) {
          return res
            .status(403)
            .send("You do not have permission to delete this submission.");
        }

        // Delete the contact form submission
        db.run(
          "DELETE FROM contact_form_submissions WHERE id = ?",
          [submissionId],
          function (err) {
            if (err) {
              console.error("Error deleting contact form submission:", err);
              return res
                .status(500)
                .send("Server error while deleting submission: " + err.message);
            }
            if (this.changes === 0) {
              return res.status(404).send("Submission not found.");
            }
            console.log(
              `Admin User ID: ${userId} deleted contact form submission ID: ${submissionId} successfully.`
            );
            res.send("Contact form submission deleted successfully.");
          }
        );
      }
    );
  }
);

app.post("/api/contact-form/submit", async (req, res) => {
  const { name, email, phone, message, turnstileToken } = req.body;
  if (!name || !phone || !message) {
    return res.status(400).send("Name, phone, and message are required.");
  }

  if (!message || message.trim() === "") {
    return res.status(400).send("Message is required.");
  }

  if (message.length > 500) {
    return res.status(400).send("Message cannot exceed 500 characters.");
  }

  if (message.length < 10) {
    return res.status(400).send("Message must be at least 10 characters long.");
  }

  if (!/^\d{10}$/.test(String(phone))) {
    return res.status(400).send("Phone number must be a 10-digit number.");
  }

  // Require Turnstile token
  if (!turnstileToken && process.env.TURNSTILES_ENABLED === "true") {
    return res.status(400).send("Missing captcha token.");
  }

  // Verify Turnstile token with Cloudflare
  if (process.env.TURNSTILES_ENABLED === "true") {
    try {
      const verifyUrl =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";
      const params = new URLSearchParams();
      params.append("secret", process.env.TURNSTILE_SECRET);
      params.append("response", turnstileToken);
      // optional: params.append("remoteip", req.ip);

      const verifyRes = await fetch(verifyUrl, {
        method: "POST",
        body: params,
      });
      const verifyJson = await verifyRes.json();
      if (!verifyJson.success) {
        console.warn("Turnstile verify failed:", verifyJson);
        return res.status(403).send("Captcha verification failed.");
      }
    } catch (err) {
      console.error("Turnstile verification error:", err);
      return res.status(500).send("Captcha verification error: " + err.message);
    }
  }

  // Insert the contact form submission into the database
  db.run(
    "INSERT INTO contact_form_submissions (name, email, phone, message) VALUES (?, ?, ?, ?)",
    [name, email, phone, message],
    function (err) {
      if (err) {
        console.error("Error submitting contact form:", err);
        return res
          .status(500)
          .send("Server error while submitting form: " + err.message);
      }
      console.log(`Contact form submitted by ${name} with phone ${phone}.`);
      res.status(201).send("Contact form submitted successfully.");
    }
  );
});

app.post("/api/user/contact-form/submit", authenticateJWT, async (req, res) => {
  const { message, phone, useAccountPhoneNumber, turnstileToken } = req.body;
  // Extract user ID from JWT
  const userId = req.user.id;
  if (!message || message.trim() === "") {
    return res.status(400).send("Message is required.");
  }
  if (message.length > 500) {
    return res.status(400).send("Message cannot exceed 500 characters.");
  }
  if (message.length < 10) {
    return res.status(400).send("Message must be at least 10 characters long.");
  }
  if (!useAccountPhoneNumber && (!phone || !/^\d{10}$/.test(String(phone)))) {
    return res.status(400).send("Phone number must be a 10-digit number.");
  }

  // Require Turnstile token
  if (!turnstileToken && process.env.TURNSTILES_ENABLED === "true") {
    return res.status(400).send("Missing captcha token.");
  }

  // Verify Turnstile token with Cloudflare
  if (process.env.TURNSTILES_ENABLED === "true") {
    try {
      const verifyUrl =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";
      const params = new URLSearchParams();
      params.append("secret", process.env.TURNSTILE_SECRET);
      params.append("response", turnstileToken);
      // optional: params.append("remoteip", req.ip);

      const verifyRes = await fetch(verifyUrl, {
        method: "POST",
        body: params,
      });
      const verifyJson = await verifyRes.json();
      if (!verifyJson.success) {
        console.warn("Turnstile verify failed:", verifyJson);
        return res.status(403).send("Captcha verification failed.");
      }
    } catch (err) {
      console.error("Turnstile verification error:", err);
      return res.status(500).send("Captcha verification error: " + err.message);
    }
  }

  const user = db.get(
    "SELECT * FROM users WHERE id = ?",
    [userId],
    (err, row) => {
      if (err) {
        console.error("Error fetching user information:", err);
        return res
          .status(500)
          .send("Server error while fetching user information: " + err.message);
      }
      if (!row) {
        return res.status(404).send("User not found.");
      }
      // User information is available in 'row'
      // Now you can insert the contact form submission into the database
      db.run(
        "INSERT INTO contact_form_submissions (name, email, phone, user_id, message) VALUES (?, ?, ?, ?, ?)",
        [
          row.first_name +
            (row.middle_name ? " " + row.middle_name : "") +
            " " +
            row.last_name,
          row.email,
          useAccountPhoneNumber ? row.phone : phone,
          userId,
          message,
        ],
        function (err) {
          if (err) {
            console.error("Error submitting contact form:", err);
            return res
              .status(500)
              .send("Server error while submitting form: " + err.message);
          }
          console.log(
            `User ID: ${userId} submitted contact form successfully.`
          );
          res.status(201).send("Contact form submitted successfully.");
        }
      );
    }
  );
});
app.get("/api/user/contact-form/submissions", authenticateJWT, (req, res) => {
  const userId = req.user.id;
  console.log(`User ID: ${userId} is fetching contact form submissions...`);
  db.all(
    "SELECT * FROM contact_form_submissions WHERE user_id = ?",
    [userId],
    (err, rows) => {
      if (err) {
        console.error("Error fetching contact form submissions:", err);
        return res
          .status(500)
          .send("Server error while fetching submissions: " + err.message);
      }
      res.json(rows);
    }
  );
});

app.delete(
  "/api/user/contact-form/submission/:id",
  authenticateJWT,
  (req, res) => {
    const submissionId = req.params.id;
    const userId = req.user.id;
    // First, fetch the submission to verify ownership
    db.get(
      "SELECT user_id FROM contact_form_submissions WHERE id = ?",
      [submissionId],
      (err, row) => {
        if (err) {
          console.error("Error fetching contact form submission:", err);
          return res.status(500).json({
            error: `Server error while fetching submission: ${err.message}`,
          });
        }
        if (!row) {
          return res.status(404).json({ error: "Submission not found." });
        }
        if (row.user_id != null && row.user_id !== userId) {
          return res.status(403).json({
            error: "You do not have permission to delete this submission.",
          });
        }
        if (row.user_id !== null) {
          // User owns the submission, proceed to delete
          db.run(
            "DELETE FROM contact_form_submissions WHERE id = ? AND user_id = ?",
            [submissionId, userId],
            function (err) {
              if (err) {
                console.error("Error deleting contact form submission:", err);
                return res.status(500).json({
                  error: `Server error while deleting submission: ${err.message}`,
                });
              }
              if (this.changes === 0) {
                return res.status(404).json({ error: "Submission not found." });
              }
              console.log(
                `User ID: ${userId} deleted contact form submission ID: ${submissionId} successfully.`
              );
              res.json({
                message: "Contact form submission deleted successfully.",
              });
            }
          );
        }
      }
    );
  }
);

// Start HTTP server for local testing
if (process.env.NODE_ENV === "production") {
  // Production: HTTPS
  const PRIV_KEY = process.env.PRIV_KEY;
  const FULL_CHAIN = process.env.FULL_CHAIN;
  const httpsOptions = {
    key: fs.readFileSync(PRIV_KEY),
    cert: fs.readFileSync(FULL_CHAIN),
  };

  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`Server is running on https://localhost:${PORT}`);
    initiateStripeSync(); // Start the initial sync
  });
} else {
  // Local development: HTTP
  app.listen(PORT, () => {
    console.log(`Server is running locally on http://localhost:${PORT}`);
    initiateStripeSync(); // Start the initial sync
  });
}
