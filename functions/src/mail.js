// Email alerts. The SMTP connection string lives in Secret Manager (secret SMTP_URL), never in the repo, e.g.
// smtps://user:app-password@smtp.gmail.com:465 . Set it to "none" to turn alerts off.
import { defineSecret } from 'firebase-functions/params';

export const SMTP_URL = defineSecret('SMTP_URL');
const FROM = 'Hamilton County Election Commission <noreply@govotehamiltontn.gov>';
let transport;

export function mailConfigured() {
  const v = (process.env.SMTP_URL || '').trim();
  return v.startsWith('smtp://') || v.startsWith('smtps://');
}
export async function sendMail(to, subject, text) {
  if (!mailConfigured()) return false;
  // Loaded on first use, so starting an instance doesn't wait for the mail library.
  transport ??= (await import('nodemailer')).default.createTransport(process.env.SMTP_URL.trim());
  await transport.sendMail({ from: process.env.SMTP_FROM || FROM, to, subject, text });
  return true;
}
