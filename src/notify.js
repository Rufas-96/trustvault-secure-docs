// Delivery of one-time codes by email (Brevo) and SMS (Twilio).
//
// A channel is "enabled" only when its provider is configured. The UI asks /api/config which
// channels are enabled and never offers one that is not, so nothing claims to work when it
// cannot. In tests, messages go to an in-memory outbox instead of a provider.
import { config } from './config.js';

const env = process.env;

export const outbox = []; // test mode only

const emailProvider = () => Boolean(env.BREVO_API_KEY && env.MAIL_FROM);
const smsProvider = () => Boolean(env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_FROM);

export function channels() {
  // Tests use the outbox; local development prints codes to the server console. Only a
  // production deployment depends on real providers being configured.
  if (!config.isProduction) return { email: true, sms: true };
  return { email: emailProvider(), sms: smsProvider() };
}

// Development without providers: print to the server console so the flow can be tried
// locally. Never used in production (channels() reports the channel as disabled there).
const devConsole = !config.isProduction && !config.isTest;

export async function sendEmail({ to, subject, text, html }) {
  if (config.isTest) {
    outbox.push({ channel: 'email', to, subject, text });
    return;
  }
  if (!emailProvider()) {
    if (devConsole) return console.log(`[dev email] to=${to} subject="${subject}"\n${text}`);
    throw new Error('Email delivery is not configured');
  }
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      sender: { email: env.MAIL_FROM, name: env.MAIL_FROM_NAME || 'TrustVault' },
      to: [{ email: to }],
      subject,
      textContent: text,
      htmlContent: html,
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Email provider refused the message (${res.status})`);
}

export async function sendSms({ to, text }) {
  if (config.isTest) {
    outbox.push({ channel: 'sms', to, text });
    return;
  }
  if (!smsProvider()) {
    if (devConsole) return console.log(`[dev sms] to=${to}\n${text}`);
    throw new Error('SMS delivery is not configured');
  }
  const body = new URLSearchParams({ To: to, From: env.TWILIO_FROM, Body: text });
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(env.TWILIO_ACCOUNT_SID)}/Messages.json`, {
    method: 'POST',
    headers: { authorization: `Basic ${Buffer.from(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`).toString('base64')}` },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`SMS provider refused the message (${res.status})`);
}

const PURPOSE_TEXT = {
  signup: ['Confirm your email', 'Use this code to confirm your email address and finish creating your TrustVault account.'],
  login_email: ['Your sign-in code', 'Use this code to sign in to TrustVault.'],
  password_reset: ['Reset your password', 'Use this code to choose a new TrustVault password. Every session on your account will be signed out.'],
};

export function codeEmail(purpose, code, minutes) {
  const [title, line] = PURPOSE_TEXT[purpose];
  const text = `${title}\n\n${line}\n\n    ${code}\n\nThe code expires in ${minutes} minutes and works once.\nIf you did not ask for this, ignore this email: nobody can use the code without also having the browser window that requested it.\n\nTrustVault`;
  // Only fixed text and the server-generated digits go into the HTML: no user input.
  const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;color:#141a2e">
<h2 style="margin:0 0 12px">${title}</h2><p>${line}</p>
<p style="font-size:32px;letter-spacing:8px;font-weight:bold;background:#eef0ff;color:#3730a3;padding:16px;text-align:center;border-radius:10px">${code}</p>
<p style="color:#4b5470;font-size:13px">The code expires in ${minutes} minutes and works once. If you did not ask for this, ignore this email.</p>
<p style="color:#7b839c;font-size:12px">TrustVault: secure document sharing</p></div>`;
  return { subject: `${code} is your TrustVault code: ${title.toLowerCase()}`, text, html };
}

export function codeSms(purpose, code, minutes) {
  const what = { login_sms: 'sign-in', second_sms: 'sign-in verification', phone_verify: 'phone verification' }[purpose] || 'verification';
  return `TrustVault ${what} code: ${code}. Expires in ${minutes} min. Never share it. If you did not request it, ignore this message.`;
}
