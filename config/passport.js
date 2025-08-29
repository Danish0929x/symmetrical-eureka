
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const AppleStrategy = require("passport-apple").Strategy;
const User = require("../models/User");

module.exports = (passport) => {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        passReqToCallback: true // Add this to access req in callback
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          // 1. Check for existing Google user (atomic operation)
          let user = await User.findOneAndUpdate(
            { googleId: profile.id },
            { $set: { lastLogin: new Date() } },
            { new: true }
          );

          if (user) return done(null, user);

          // 2. Check for existing email user (atomic operation)
          const email = profile.emails[0].value;
          user = await User.findOneAndUpdate(
            { email },
            {
              $set: {
                googleId: profile.id,
                lastLogin: new Date(),
                ...(!req.user?.avatar && profile.photos?.[0]?.value 
                  ? { avatar: profile.photos[0].value } 
                  : {})
              },
              $addToSet: { authMethods: "google" }
            },
            { new: true }
          );

          if (user) {
            // Scenario 1: Existing email user adding Google auth
            if (!user.isEmailVerified) {
              await User.findByIdAndUpdate(user._id, {
                $set: { isEmailVerified: true }
              });
            }
            return done(null, user);
          }

          // 3. Create new Google user (atomic operation)
          user = await User.create({
            googleId: profile.id,
            name: profile.displayName,
            email,
            avatar: profile.photos?.[0]?.value || "",
            authMethods: ["google"],
            isEmailVerified: true,
            lastLogin: new Date()
          });

          return done(null, user);

        } catch (error) {
          console.error("Google OAuth error:", error);
          return done(error, null);
        }
      }
    )
  );

  // Apple OAuth Strategy
  passport.use(
    new AppleStrategy(
      {
        clientID: process.env.APPLE_CLIENT_ID,
        teamID: process.env.APPLE_TEAM_ID,
        keyID: process.env.APPLE_KEY_ID,
        privateKeyString: process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        callbackURL: process.env.APPLE_CALLBACK_URL,
        passReqToCallback: true
      },
      async (req, accessToken, refreshToken, idToken, profile, done) => {
        try {
          // Apple profile may not have email if user hides it
          const email = profile.email || (idToken && idToken.email);
          let user = await User.findOneAndUpdate(
            { appleId: profile.id },
            { $set: { lastLogin: new Date() } },
            { new: true }
          );
          if (user) return done(null, user);

          // Check for existing email user
          if (email) {
            user = await User.findOneAndUpdate(
              { email },
              {
                $set: {
                  appleId: profile.id,
                  lastLogin: new Date(),
                  name: profile.displayName || profile.name || "Apple User"
                },
                $addToSet: { authMethods: "apple" }
              },
              { new: true }
            );
            if (user) {
              if (!user.isEmailVerified) {
                await User.findByIdAndUpdate(user._id, {
                  $set: { isEmailVerified: true }
                });
              }
              return done(null, user);
            }
          }

          // Create new Apple user
          user = await User.create({
            appleId: profile.id,
            name: profile.displayName || profile.name || "Apple User",
            email,
            authMethods: ["apple"],
            isEmailVerified: true,
            lastLogin: new Date()
          });
          return done(null, user);
        } catch (error) {
          console.error("Apple OAuth error:", error);
          return done(error, null);
        }
      }
    )
  );

  // Session serialization
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
};