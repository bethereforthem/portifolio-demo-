// Server-only mailer for password-reset emails.
// Uses Gmail SMTP with an App Password from the environment (.env).
// These credentials never leave the server and are never logged.
import nodemailer from "nodemailer";

const MAX_EMAIL_LENGTH = 254;

export class MailError extends Error {
  constructor(message) {
    super(message);
    this.name = "MailError";
  }
}

let transporter;

function getTransporter() {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) {
    throw new MailError(
      "Email is not configured: set GMAIL_USER and GMAIL_APP_PASSWORD in the server's .env file.",
    );
  }
  transporter ??= nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // STARTTLS
    auth: { user, pass },
  });
  return transporter;
}

export function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= MAX_EMAIL_LENGTH &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

export async function sendPasswordResetEmail({ to, resetUrl, name }) {
  if (!isValidEmail(to)) throw new MailError("Invalid recipient address.");
  const from = process.env.GMAIL_USER;
  const displayName = String(name || "").replace(/[<>"]/g, "").trim();

  const text = [
    `Hello${displayName ? " " + displayName : ""},`,
    "",
    "Someone (hopefully you) asked to reset the password for your ThickBing Lin Cyber account.",
    "",
    "Open this link to set a new password (valid for 30 minutes, single use):",
    resetUrl,
    "",
    "If you did not request this, you can safely ignore this email — your password will not change.",
    "",
    "Stay secure,",
    "ThickBing Lin Cyber Security Operations Center",
  ].join("\n");

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;background:#0b1220;padding:32px;color:#e2e8f0">
      <div style="max-width:520px;margin:auto;background:#111a2e;border:1px solid #22304d;border-radius:16px;padding:32px">
        <p style="font-size:13px;letter-spacing:2px;color:#38bdf8;font-weight:700;margin:0 0 16px">THICKBING LIN CYBER</p>
        <h1 style="font-size:22px;color:#fff;margin:0 0 12px">Reset your password</h1>
        <p style="font-size:15px;line-height:1.6;color:#cbd5e1;margin:0 0 24px">
          Hello${displayName ? ` ${displayName}` : ""}, we received a request to reset the password for your account.
          The link below is valid for <strong style="color:#34d399">30 minutes</strong> and can be used once.
        </p>
        <a href="${resetUrl}" style="display:inline-block;background:linear-gradient(90deg,#0ea5e9,#10b981);color:#0b1220;font-weight:700;text-decoration:none;padding:14px 28px;border-radius:10px;font-size:15px">
          Set a New Password
        </a>
        <p style="font-size:13px;line-height:1.6;color:#94a3b8;margin:24px 0 0">
          If the button does not work, copy and paste this link into your browser:<br/>
          <span style="color:#38bdf8;word-break:break-all">${resetUrl}</span>
        </p>
        <p style="font-size:13px;line-height:1.6;color:#94a3b8;margin:20px 0 0">
          Did not request this? You can ignore this email — your password stays unchanged.
        </p>
        <hr style="border:none;border-top:1px solid #22304d;margin:24px 0" />
        <p style="font-size:12px;color:#64748b;margin:0">
          &copy; ThickBing Lin Cyber &middot; Security Operations Center<br/>
          This is an automated security email — please do not reply.
        </p>
      </div>
    </div>`;

  await getTransporter().sendMail({
    from: `"ThickBing Lin Cyber" <${from}>`,
    to,
    subject: "Reset your ThickBing Lin Cyber password",
    text,
    html,
  });
}
