const express = require("express")
const passport = require("passport")
const { body } = require("express-validator")
const authController = require("../controllers/authController")
const auth = require("../middleware/auth")

const router = express.Router()

// Validation rules
const registerValidation = [
  body("name").trim().isLength({ min: 2 }).withMessage("Name must be at least 2 characters"),
  body("email").isEmail().normalizeEmail().withMessage("Please provide a valid email"),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password must contain at least one uppercase letter, one lowercase letter, and one number"),
]

const loginValidation = [
  body("email").isEmail().normalizeEmail().withMessage("Please provide a valid email"),
  body("password").notEmpty().withMessage("Password is required"),
]

const forgotPasswordValidation = [body("email").isEmail().normalizeEmail().withMessage("Please provide a valid email")]

const resetPasswordValidation = [
  body("token").notEmpty().withMessage("Reset token is required"),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage("Password must contain at least one uppercase letter, one lowercase letter, and one number"),
]

// Authentication routes
router.post("/register", registerValidation, authController.register)
router.post("/verify-email", authController.verifyEmail)
router.post("/resend-verification", authController.resendVerification)
router.post("/login", loginValidation, authController.login)
router.post("/forgot-password", forgotPasswordValidation, authController.forgotPassword)
router.post("/reset-password", resetPasswordValidation, authController.resetPassword)
router.get("/me", auth, authController.getMe)

// Google OAuth routes
router.get(
  "/google",
  passport.authenticate("google", { 
    scope: ["profile", "email"],
    prompt: "select_account"
  })
);
router.get(
  "/google/callback",
  passport.authenticate("google", { 
    failureRedirect: "/login",
    session: false
   }),
  authController.googleSuccess,
)

// Apple OAuth routes
router.get(
  "/apple",
  passport.authenticate("apple", {
    scope: ["name", "email"],
  })
);
router.get(
  "/apple/callback",
  passport.authenticate("apple", {
    failureRedirect: "/login",
    session: false
  }),
  authController.appleSuccess
);

router.post(
  "/apple/callback",
  passport.authenticate("apple", {
    failureRedirect: "/login",
    session: false
  }),
  authController.appleSuccess
);

module.exports = router
