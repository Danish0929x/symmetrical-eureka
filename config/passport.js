const GoogleStrategy = require("passport-google-oauth20").Strategy;
const AppleStrategy = require("passport-apple").Strategy;
const User = require("../models/User");

module.exports = (passport) => {
  // Google Strategy (existing - keep as is)
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        passReqToCallback: true
      },
      async (req, accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOneAndUpdate(
            { googleId: profile.id },
            { $set: { lastLogin: new Date() } },
            { new: true }
          );

          if (user) return done(null, user);

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
            if (!user.isEmailVerified) {
              await User.findByIdAndUpdate(user._id, {
                $set: { isEmailVerified: true }
              });
            }
            return done(null, user);
          }

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

  // Fixed Apple Strategy
  passport.use(
    new AppleStrategy(
      {
        clientID: process.env.APPLE_CLIENT_ID,
        teamID: process.env.APPLE_TEAM_ID,
        keyID: process.env.APPLE_KEY_ID,
        privateKeyString: process.env.APPLE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        callbackURL: process.env.APPLE_CALLBACK_URL,
        scope: ["name", "email"],
        passReqToCallback: true
      },
      async (req, accessToken, refreshToken, idToken, profile, done) => {
        try {
          console.log("Apple OAuth Debug:");
          console.log("Profile:", JSON.stringify(profile, null, 2));
          console.log("ID Token:", idToken);
          
          // Apple's profile structure is different
          let email, appleId, name;
          
          if (profile) {
            appleId = profile.sub || profile.id;
            email = profile.email;
            
            // Handle name from profile or form data
            if (profile.name) {
              if (typeof profile.name === 'string') {
                name = profile.name;
              } else {
                name = `${profile.name.firstName || ''} ${profile.name.lastName || ''}`.trim();
              }
            }
          }
          
          // Fallback: get data from form submission (first-time Apple login)
          if (req.body?.user) {
            const userData = JSON.parse(req.body.user);
            email = email || userData.email;
            if (userData.name && !name) {
              name = `${userData.name.firstName || ''} ${userData.name.lastName || ''}`.trim();
            }
          }
          
          // Final fallbacks
          appleId = appleId || profile?.sub;
          name = name || email?.split('@')[0] || 'Apple User';
          
          if (!appleId) {
            console.error("No Apple ID found in profile");
            return done(new Error("Apple ID not found"), null);
          }

          console.log(`Processing Apple login for: ${email} (ID: ${appleId})`);

          // 1. Check for existing Apple user
          let user = await User.findOneAndUpdate(
            { appleId: appleId },
            { $set: { lastLogin: new Date() } },
            { new: true }
          ).select('+authMethods');

          if (user) {
            console.log("Found existing Apple user");
            return done(null, user);
          }

          // 2. Check for existing email user (if email available)
          if (email) {
            user = await User.findOneAndUpdate(
              { email },
              {
                $set: {
                  appleId: appleId,
                  lastLogin: new Date(),
                  isEmailVerified: true // Apple emails are verified
                },
                $addToSet: { authMethods: "apple" }
              },
              { new: true }
            ).select('+authMethods');

            if (user) {
              console.log("Linked Apple to existing email user");
              return done(null, user);
            }
          }

          // 3. Create new Apple user
          console.log("Creating new Apple user");
          user = await User.create({
            appleId: appleId,
            name: name,
            email: email || `apple_${appleId}@example.com`, // Fallback email
            authMethods: ["apple"],
            isEmailVerified: true,
            lastLogin: new Date()
          });

          console.log("Apple user created successfully:", user._id);
          return done(null, user);

        } catch (error) {
          console.error("Apple OAuth detailed error:", error);
          return done(error, null);
        }
      }
    )
  );

  // Session serialization
  passport.serializeUser((user, done) => {
    done(null, user._id);
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