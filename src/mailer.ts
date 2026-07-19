// SSO — відправка листів через SMTP (відновлення пароля).
// Активується, коли задано SMTP_HOST. Креди — у .env (український хостинг).
import nodemailer, { type Transporter } from 'nodemailer';

let transporter: Transporter | null = null;

export function smtpEnabled(): boolean {
  return Boolean(process.env.SMTP_HOST);
}

function getTransporter(): Transporter {
  if (transporter) return transporter;
  const port = Number(process.env.SMTP_PORT || 587);
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    // secure=true для 465 (SSL); для 587 — STARTTLS (secure=false)
    secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465,
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined,
  });
  return transporter;
}

const FROM = () => process.env.SMTP_FROM || `FINEKO <${process.env.SMTP_USER || 'no-reply@fineko.space'}>`;

function resetHtml(link: string): string {
  return `<!doctype html><html lang="uk"><body style="margin:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;color:#1a1a1a">
  <div style="max-width:480px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e6e8eb">
    <div style="background:#111;padding:20px 28px;color:#fff;font-size:18px;font-weight:700">🔐 FINEKO</div>
    <div style="padding:28px">
      <h1 style="font-size:18px;margin:0 0 12px">Скидання пароля</h1>
      <p style="font-size:14px;line-height:1.5;color:#444;margin:0 0 20px">Ви (або хтось) попросили скинути пароль до акаунта FINEKO. Натисніть кнопку нижче, щоб задати новий пароль. Посилання дійсне 1 годину.</p>
      <a href="${link}" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-size:14px;font-weight:600">Задати новий пароль</a>
      <p style="font-size:12px;color:#888;margin:22px 0 0;word-break:break-all">Якщо кнопка не працює, скопіюйте посилання:<br>${link}</p>
      <p style="font-size:12px;color:#888;margin:14px 0 0">Якщо ви не просили скидання — просто проігноруйте цей лист, пароль лишиться незмінним.</p>
    </div>
  </div></body></html>`;
}

/** Надіслати лист зі скиданням пароля. Кидає помилку, якщо SMTP не спрацював. */
export async function sendResetEmail(to: string, link: string): Promise<void> {
  await getTransporter().sendMail({
    from: FROM(),
    to,
    subject: 'FINEKO — скидання пароля',
    text: `Скидання пароля до акаунта FINEKO.\nПосилання (дійсне 1 годину): ${link}\nЯкщо ви не просили — проігноруйте цей лист.`,
    html: resetHtml(link),
  });
}
