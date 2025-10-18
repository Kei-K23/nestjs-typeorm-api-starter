import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as nodemailer from 'nodemailer';
import { Setting } from 'src/setting/entities/setting.entity';

@Injectable()
export class EmailServiceUtils {
  private readonly logger = new Logger(EmailServiceUtils.name);

  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
  ) {}

  private async getTransporter() {
    const smtpSettings = await this.getSMTPSettings();

    if (!smtpSettings.smtpEnabled) {
      throw new Error('SMTP is not enabled');
    }

    return nodemailer.createTransport({
      host: smtpSettings.smtpHost,
      port: smtpSettings.smtpPort,
      secure: smtpSettings.smtpSecure,
      auth:
        smtpSettings.smtpUsername && smtpSettings.smtpPassword
          ? {
              user: smtpSettings.smtpUsername,
              pass: smtpSettings.smtpPassword,
            }
          : undefined,
    });
  }

  private async getSMTPSettings() {
    const smtpKeys = [
      'smtp_host',
      'smtp_port',
      'smtp_secure',
      'smtp_username',
      'smtp_password',
      'smtp_from_email',
      'smtp_from_name',
      'smtp_enabled',
    ];

    const settings = await this.settingRepository.find({
      where: smtpKeys.map((key) => ({ key })),
    });

    return {
      smtpHost: this.getSettingValue(settings, 'smtp_host'),
      smtpPort: parseInt(this.getSettingValue(settings, 'smtp_port') || '587'),
      smtpSecure: this.getSettingValue(settings, 'smtp_secure') === 'true',
      smtpUsername: this.getSettingValue(settings, 'smtp_username'),
      smtpPassword: this.getSettingValue(settings, 'smtp_password'),
      smtpFromEmail: this.getSettingValue(settings, 'smtp_from_email'),
      smtpFromName: this.getSettingValue(settings, 'smtp_from_name'),
      smtpEnabled: this.getSettingValue(settings, 'smtp_enabled') === 'true',
    };
  }

  private getSettingValue(settings: Setting[], key: string): string {
    const setting = settings.find((s) => s.key === key);
    return setting?.value || '';
  }

  async sendTwoFactorCode(
    email: string,
    code: string,
    userName: string,
  ): Promise<void> {
    try {
      const transporter = await this.getTransporter();
      const smtpSettings = await this.getSMTPSettings();
      console.log(smtpSettings, ' here call');

      const mailOptions = {
        from: `"${smtpSettings.smtpFromName}" <${smtpSettings.smtpFromEmail}>`,
        to: email,
        subject: 'Two-Factor Authentication Code - OBS CRM',
        html: this.getTwoFactorEmailTemplate(code, userName),
      };

      await transporter.sendMail(mailOptions);
      this.logger.log(`2FA code sent successfully to ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send 2FA code to ${email}:`, error);
      throw new Error('Failed to send verification email');
    }
  }

  private getTwoFactorEmailTemplate(code: string, userName: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Two-Factor Authentication Code</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #2c5aa0; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
          .code-box { background: #fff; border: 2px solid #2c5aa0; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
          .code { font-size: 32px; font-weight: bold; color: #2c5aa0; letter-spacing: 5px; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Two-Factor Authentication</h1>
          </div>
          <div class="content">
            <h2>Hello ${userName},</h2>
            <p>You have requested to enable Two-Factor Authentication for your OBS CRM account. Please use the verification code below to complete the setup:</p>
            
            <div class="code-box">
              <div class="code">${code}</div>
            </div>
            
            <div class="warning">
              <strong>⚠️ Important:</strong>
              <ul>
                <li>This code will expire in 10 minutes</li>
                <li>Do not share this code with anyone</li>
                <li>If you didn't request this, please contact your administrator immediately</li>
              </ul>
            </div>
            
            <p>If you have any questions or need assistance, please contact our support team.</p>
            
            <p>Best regards,<br>
            <strong>OBS CRM Team</strong></p>
          </div>
          <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}
