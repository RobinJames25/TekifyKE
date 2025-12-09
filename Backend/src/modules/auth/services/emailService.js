import nodemailer from 'nodemailer';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import handlebars from 'handlebars';
import logger from '../utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class EmailService {
  static transporter = null;
  static templates = new Map();
  static initialized = false;
  
  /**
   * Initialize email service
   */
  static async initialize() {
    if (this.initialized) return;
    
    // Validate environment variables
      const requiredEnvVars = [
          'SMTP_HOST',
          'SMTP_PORT', 
          'SMTP_USER', 
          'SMTP_PASS',
          'EMAIL_FROM'
      ];
    for (const envVar of requiredEnvVars) {
      if (!process.env[envVar]) {
        logger.error(`Missing required environment variable: ${envVar}`);
        throw new Error(`Email service configuration incomplete: ${envVar} is required`);
      }
    }
    
    try {
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        },
        pool: true, // Use connection pooling
        maxConnections: 5,
        maxMessages: 100
      });
      
      // Verify connection
      await this.transporter.verify();
      logger.info('✅ SMTP connection established successfully');
      
      // Load templates
      await this.loadTemplates();
      
      this.initialized = true;
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      throw error;
    }
  }
  
  /**
   * Load email templates
   */
  static async loadTemplates() {
    const templatesDir = path.join(__dirname, '../../templates/email');
    
    try {
      const files = await fs.readdir(templatesDir);
      
      for (const file of files) {
        if (file.endsWith('.html')) {
          const templateName = file.replace('.html', '');
          const templatePath = path.join(templatesDir, file);
          
          try {
            const templateContent = await fs.readFile(templatePath, 'utf8');
            const template = handlebars.compile(templateContent);
            this.templates.set(templateName, template);
            
            logger.debug(`Loaded email template: ${templateName}`);
          } catch (error) {
            logger.error(`Failed to load template ${file}:`, error);
          }
        }
      }
    } catch (error) {
      logger.warn('No email templates directory found, using default templates');
    }
  }
  
  /**
   * Get compiled template
   */
  static getTemplate(templateName, data = {}) {
    const template = this.templates.get(templateName);
    
    if (template) {
      return template(data);
    }
    
    // Fallback to default template
    return this.getDefaultTemplate(data);
  }
  
  /**
   * Default email template
   */
  static getDefaultTemplate(data) {
    const year = new Date().getFullYear();
    const appName = process.env.APP_NAME || 'Electronics Shop';
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@electronics.com';
    
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${data.subject || 'Notification'}</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            text-align: center;
            border-radius: 10px 10px 0 0;
          }
          .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
          }
          .content {
            background: white;
            padding: 40px;
            border-radius: 0 0 10px 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .button {
            display: inline-block;
            padding: 14px 28px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            transition: transform 0.2s, box-shadow 0.2s;
          }
          .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(102, 126, 234, 0.2);
          }
          .footer {
            text-align: center;
            padding: 30px 20px;
            color: #666;
            font-size: 14px;
            border-top: 1px solid #eee;
            margin-top: 30px;
          }
          .alert {
            background: #fff3cd;
            border: 1px solid #ffecb5;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
          }
          .code {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 18px;
            text-align: center;
            letter-spacing: 2px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${appName}</h1>
          </div>
          <div class="content">
            ${data.content || data.message || ''}
            ${data.buttonUrl ? `<a href="${data.buttonUrl}" class="button">${data.buttonText || 'Click Here'}</a>` : ''}
            ${data.code ? `<div class="code">${data.code}</div>` : ''}
            ${data.alert ? `<div class="alert">${data.alert}</div>` : ''}
          </div>
          <div class="footer">
            <p>© ${year} ${appName}. All rights reserved.</p>
            <p>Need help? Contact us at <a href="mailto:${supportEmail}">${supportEmail}</a></p>
            <p>This is an automated message, please do not reply to this email.</p>
            <p style="font-size: 12px; color: #999;">
              If you didn't request this email, you can safely ignore it.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
  
  /**
   * Send email with error handling and retry logic
   */
  static async sendEmail(to, subject, html, text = '', options = {}) {
    if (!this.initialized) {
      await this.initialize();
    }
    
    const mailOptions = {
      from: `"${process.env.APP_NAME || 'Electronics Shop'}" <${process.env.EMAIL_FROM}>`,
      to,
      subject,
      html,
      text: text || this.htmlToText(html),
      ...options
    };
    
    let attempts = 0;
    const maxAttempts = 3;
    
    while (attempts < maxAttempts) {
      try {
        attempts++;
        
        const info = await this.transporter.sendMail(mailOptions);
        
        logger.info(`Email sent to ${to} (attempt ${attempts}): ${info.messageId}`, {
          messageId: info.messageId,
          to,
          subject
        });
        
        return {
          success: true,
          messageId: info.messageId,
          attempts
        };
        
      } catch (error) {
        logger.error(`Failed to send email to ${to} (attempt ${attempts}):`, error);
        
        if (attempts === maxAttempts) {
          // Log critical failure
          logger.error(`Failed to send email after ${maxAttempts} attempts:`, {
            to,
            subject,
            error: error.message
          });
          
          return {
            success: false,
            error: error.message,
            attempts
          };
        }
        
        // Exponential backoff before retry
        const delay = Math.pow(2, attempts) * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  /**
   * Convert HTML to plain text
   */
  static htmlToText(html) {
    return html
      .replace(/<style[^>]*>.*?<\/style>/gs, '')
      .replace(/<script[^>]*>.*?<\/script>/gs, '')
      .replace(/<[^>]*>/g, ' ')
      .replace(/\s+/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
  }
  
  /**
   * Specific email functions
   */
  
  static async sendVerificationEmail(email, token, name = 'Customer') {
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    
    const html = this.getTemplate('verify-email', {
      name,
      verificationUrl,
      subject: 'Verify Your Email Address',
      buttonText: 'Verify Email',
      alert: 'This link will expire in 24 hours.'
    });
    
    return this.sendEmail(
      email,
      'Verify Your Email Address - Electronics Shop',
      html
    );
  }
  
  static async sendWelcomeEmail(email, name) {
    const loginUrl = `${process.env.FRONTEND_URL}/login`;
    const dashboardUrl = `${process.env.FRONTEND_URL}/dashboard`;
    
    const html = this.getTemplate('welcome', {
      name,
      loginUrl,
      dashboardUrl,
      subject: 'Welcome to Electronics Shop!',
      buttonText: 'Go to Dashboard'
    });
    
    return this.sendEmail(
      email,
      'Welcome to Electronics Shop!',
      html
    );
  }
  
  static async sendPasswordResetEmail(email, token, name = 'Customer') {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    
    const html = this.getTemplate('reset-password', {
      name,
      resetUrl,
      subject: 'Reset Your Password',
      buttonText: 'Reset Password',
      alert: 'This link will expire in 1 hour. If you didn\'t request this, please ignore this email.'
    });
    
    return this.sendEmail(
      email,
      'Reset Your Password - Electronics Shop',
      html
    );
  }
  
  static async sendPasswordChangedEmail(email, name = 'Customer') {
    const html = this.getTemplate('password-changed', {
      name,
      subject: 'Password Changed Successfully',
      alert: 'If you didn\'t make this change, please contact our support team immediately.',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@electronics.com'
    });
    
    return this.sendEmail(
      email,
      'Password Changed Successfully',
      html
    );
  }
  
  static async sendTwoFactorEmail(email, name, code) {
    const html = this.getTemplate('two-factor', {
      name,
      code,
      subject: 'Your Two-Factor Authentication Code',
      alert: 'This code will expire in 10 minutes. Do not share this code with anyone.'
    });
    
    return this.sendEmail(
      email,
      'Your Two-Factor Authentication Code',
      html
    );
  }
  
  static async sendSecurityAlertEmail(email, name, alertType, details = {}) {
    const html = this.getTemplate('security-alert', {
      name,
      alertType,
      details,
      subject: 'Security Alert - Unusual Activity Detected',
      alert: 'If this wasn\'t you, please secure your account immediately.',
      supportEmail: process.env.SUPPORT_EMAIL
    });
    
    return this.sendEmail(
      email,
      'Security Alert - Unusual Activity Detected',
      html
    );
  }
  
  static async sendAccountLockedEmail(email, name, unlockTime) {
    const html = this.getTemplate('account-locked', {
      name,
      unlockTime,
      subject: 'Account Temporarily Locked',
      alert: 'Your account has been locked due to multiple failed login attempts.',
      supportEmail: process.env.SUPPORT_EMAIL
    });
    
    return this.sendEmail(
      email,
      'Account Temporarily Locked - Electronics Shop',
      html
    );
  }
}

// Auto-initialize on import
EmailService.initialize().catch(error => {
  logger.error('Failed to auto-initialize email service:', error);
});

export default EmailService;