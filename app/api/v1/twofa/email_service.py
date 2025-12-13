import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# CONFIG SMTP 
SMTP_USER = "julianavilacaicedo2003@gmail.com"      # remitente (puede ser tu dominio)
SMTP_PASS = "zcrw zqdb xchf ohzi"        # contraseña de app / token SMTP
SMTP_SERVER = "smtp.gmail.com"          # servidor SMTP real
SMTP_PORT = 587                         # puerto TLS típico


def build_html_body(code: str, username: str | None, email_to: str) -> str:
    display_name = username or email_to

    return f"""
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Código de verificación - VULNPORTS</title>
</head>
<body style="margin:0; padding:0; background-color:#020617; font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#020617; padding:24px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background:#0b1220; border-radius:16px; overflow:hidden; border:1px solid rgba(0,238,255,0.3);">
          
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#00eaff,#38bdf8); padding:20px 24px;" align="left">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="left">
                    <div style="display:flex; align-items:center; gap:8px;">
                      <span style="display:inline-block; width:32px; height:32px; border-radius:50%; background:#020617; color:#00eaff; text-align:center; line-height:32px; font-weight:700; font-size:18px;">V</span>
                      <span style="font-size:20px; font-weight:700; color:#020617;">VULNPORTS</span>
                    </div>
                    <div style="color:#020617; font-size:12px; margin-top:4px;">
                      Sistema de Seguridad y Escaneo de Puertos
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:24px;">
              <p style="margin:0 0 8px; color:#e5e7eb; font-size:16px;">
                Hola <strong>{display_name}</strong>,
              </p>

              <p style="margin:0 0 16px; color:#9ca3af; font-size:14px; line-height:1.5;">
                Estás intentando iniciar sesión o activar la autenticación de dos factores (2FA) en
                <strong style="color:#00eaff;">VULNPORTS</strong>.
              </p>

              <p style="margin:0 0 8px; color:#e5e7eb; font-size:14px;">
                Tu código de verificación es:
              </p>

              <div style="
                  margin:16px 0 20px;
                  padding:14px 24px;
                  border-radius:12px;
                  background:rgba(15,23,42,0.9);
                  border:1px solid rgba(0,238,255,0.4);
                  text-align:center;
                ">
                <span style="font-size:28px; letter-spacing:6px; font-weight:700; color:#00eaff;">
                  {code}
                </span>
              </div>

              <p style="margin:0 0 12px; color:#9ca3af; font-size:13px; line-height:1.5;">
                Este código es válido por <strong>10 minutos</strong>.  
                Si no fuiste tú quien realizó esta acción, te recomendamos cambiar tu contraseña
                y revisar la actividad de tu cuenta.
              </p>

              <p style="margin:0; color:#6b7280; font-size:12px;">
                Por tu seguridad, nunca compartas este código con nadie.
                El equipo de VULNPORTS nunca te lo solicitará por correo.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:16px 24px 20px; border-top:1px solid #1f2933;">
              <p style="margin:0; color:#4b5563; font-size:11px; line-height:1.5;">
                Este mensaje fue enviado automáticamente por VULNPORTS.  
                Si no reconoces esta actividad, por favor ignora este correo.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    """


def build_text_body(code: str) -> str:
    """Versión texto plano (fallback para clientes que no leen HTML)."""
    return f"""Tu código de verificación para VULNPORTS es:

    {code}

Este código expira en 10 minutos.
Si no solicitaste este código, ignora este mensaje.
"""


def send_email_code(email_to: str, code: str, username: str | None = None) -> bool:
    """
    Envía el código 2FA por correo usando HTML + texto plano.
    """
    # Cuerpo
    text_body = build_text_body(code)
    html_body = build_html_body(code, username, email_to)

    # Mensaje multi-parte (texto + html)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Código de verificación - VULNPORTS"
    msg["From"] = SMTP_USER
    msg["To"] = email_to

    part_text = MIMEText(text_body, "plain", "utf-8")
    part_html = MIMEText(html_body, "html", "utf-8")

    msg.attach(part_text)
    msg.attach(part_html)

    # Envío
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [email_to], msg.as_string())

    return True
