
require("dotenv").config();

const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 5000;

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

const allowedOrigins = (process.env.FRONTEND_URL || "http://127.0.0.1:5500,http://localhost:5500")
  .split(",")
  .map((origin) => origin.trim());

app.use(cors({
  origin(origin, callback) {
    // Allow tools such as curl that do not send an Origin header.
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed by CORS"));
  }
}));

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many messages. Please try again in 15 minutes."
  }
});

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD
  }
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

app.get("/api/health", (_req, res) => {
  res.json({ success: true, message: "Portfolio contact API is running." });
});

app.post("/api/contact", contactLimiter, async (req, res) => {
  try {
    const { name, email, subject, message, website } = req.body || {};

    // Honeypot field: ordinary visitors should leave this empty.
    if (website) {
      return res.json({
        success: true,
        message: "Your message has been received."
      });
    }

    if (![name, email, subject, message].every(
      (value) => typeof value === "string" && value.trim()
    )) {
      return res.status(400).json({
        success: false,
        message: "Please complete all required fields."
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim();
    const cleanSubject = subject.trim();
    const cleanMessage = message.trim();

    if (
      cleanName.length > 100 ||
      cleanEmail.length > 254 ||
      cleanSubject.length > 150 ||
      cleanMessage.length > 5000
    ) {
      return res.status(400).json({
        success: false,
        message: "One or more fields exceed the allowed length."
      });
    }

    // Basic email format check.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address."
      });
    }

    await transporter.sendMail({
      from: `"Aditya Portfolio Contact" <${process.env.EMAIL_USER}>`,
      to: process.env.RECEIVING_EMAIL,
      replyTo: {
        name: cleanName,
        address: cleanEmail
      },
      subject: `Portfolio contact: ${cleanSubject}`,
      text: [
        "You received a new message from your portfolio.",
        "",
        `Name: ${cleanName}`,
        `Email: ${cleanEmail}`,
        `Subject: ${cleanSubject}`,
        "",
        "Message:",
        cleanMessage
      ].join("\n"),
      html: `
        <h2>New Portfolio Message</h2>
        <p><strong>Name:</strong> ${escapeHtml(cleanName)}</p>
        <p><strong>Email:</strong> ${escapeHtml(cleanEmail)}</p>
        <p><strong>Subject:</strong> ${escapeHtml(cleanSubject)}</p>
        <p><strong>Message:</strong></p>
        <p>${escapeHtml(cleanMessage).replace(/\n/g, "<br>")}</p>
      `
    });

    return res.status(200).json({
      success: true,
      message: "Message sent successfully! Thank you for contacting me."
    });
  } catch (error) {
    // Keep credentials and technical details out of public responses.
    console.error("Contact email error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Sorry, your message could not be sent. Please try again later."
    });
  }
});

app.listen(PORT, () => {
  console.log(`Portfolio API running at http://localhost:${PORT}`);
});
