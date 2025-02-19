import axios, { AxiosInstance } from 'axios';
import crypto from 'crypto';

interface OrvioClientOptions {
  /** Custom base URL for the API (default: 'https://orvio.pavit.xyz') */
  baseURL?: string;
}

/**
 * Options for creating an OTP request
 */
interface CreateOtpOptions {
  /** 
   * Webhook URL to receive OTP events
   * Events will be sent for OTP sent, verified, and expired statuses
   */
  webhookUrl?: string;

  /**
   * Secret key used to sign webhook payloads
   * Use this to verify incoming webhooks using OrvioClient.verifyWebhookSignature
   */
  webhookSecret?: string;
}

interface CreateOtpResponse {
  /** Transaction ID used for verification */
  tid: string;
  /** Status message from the server */
  message: string;
  /** Whether the OTP was sent successfully */
  success: boolean;
}

interface VerifyOtpResponse {
  /** Whether the API call was successful */
  success: boolean;
  /** Status message from the server */
  message: string;
  /** Whether the OTP was correct */
  verified: boolean;
}

/**
 * Events that can be received through webhooks
 */
interface WebhookEvent {
  /** Type of the webhook event */
  event: 'OTP_SENT' | 'OTP_VERIFIED' | 'OTP_EXPIRED';
  /** Transaction ID associated with the event */
  tid: string;
  /** Phone number the OTP was sent to */
  phoneNumber: string;
  /** ISO timestamp of when the event occurred */
  timestamp: string;
  /** Whether the operation was successful */
  success: boolean;
  /** Optional message providing more details */
  message?: string;
}

export class OrvioClient {
  private baseURL: string;
  private apiKey: string;
  private accessToken: string | null;
  private api: AxiosInstance;

  /**
   * Creates a new Orvio client instance
   * @param apiKey - Your Orvio API key
   * @param options - Additional configuration options
   */
  constructor(apiKey: string, options: OrvioClientOptions = {}) {
    this.baseURL = options.baseURL || 'https://orvio.pavit.xyz';
    this.apiKey = apiKey;
    this.accessToken = null;
    this.api = this.initializeApi();
  }

  private initializeApi(): AxiosInstance {
    const api = axios.create({
      baseURL: this.baseURL,
    });

    api.interceptors.request.use((config) => {
      if (this.accessToken) {
        config.headers.Authorization = `Bearer ${this.accessToken}`;
      }
      return config;
    });

    api.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          try {
            const response = await axios.post(`${this.baseURL}/auth/refresh`, {
              refreshToken: this.apiKey,
            });
            this.accessToken = response.data.accessToken;
            error.config.headers.Authorization = `Bearer ${this.accessToken}`;
            return axios(error.config);
          } catch (refreshError: any) {
            if (refreshError.response?.status === 403) {
              throw new Error('Invalid API key');
            }
            throw refreshError;
          }
        }
        if (error.response?.status === 403) {
          throw new Error('Session invalid');
        }
        throw error;
      }
    );

    return api;
  }

  /**
   * Sends an OTP to the specified phone number
   * @param phoneNumber - The phone number to send the OTP to (E.164 format, e.g., '+1234567890')
   * @param options - Optional webhook configuration for receiving status updates
   * @returns Promise containing the transaction ID and status
   * @example
   * ```typescript
   * const { tid } = await client.create('+1234567890', {
   *   webhookUrl: 'https://your-server.com/webhook',
   *   webhookSecret: 'your_webhook_secret'
   * });
   * ```
   */
  async create(phoneNumber: string, options: CreateOtpOptions = {}): Promise<CreateOtpResponse> {
    const payload = {
      phoneNumber,
      reportingCustomerWebhook: options.webhookUrl,
      reportingCustomerWebhookSecret: options.webhookSecret
    };
    
    const response = await this.api.post<CreateOtpResponse>('/service/sendOtp', payload);
    return response.data;
  }

  /**
   * Verifies an OTP using the transaction ID
   * @param tid - The transaction ID received from create()
   * @param userInputOtp - The OTP entered by the user
   * @returns Promise containing the verification status
   * @example
   * ```typescript
   * const result = await client.verify(tid, '123456');
   * if (result.verified) {
   *   // OTP was correct
   * }
   * ```
   */
  async verify(tid: string, userInputOtp: string): Promise<VerifyOtpResponse> {
    const response = await this.api.post<VerifyOtpResponse>('/service/verifyOtp', { 
      tid, 
      userInputOtp 
    });
    return response.data;
  }

  /**
   * Utility function to verify webhook signatures
   * @param payload - The raw webhook payload as string
   * @param signature - The X-Signature header from the webhook request
   * @param webhookSecret - Your webhook secret
   * @returns Whether the signature is valid
   * @example
   * ```typescript
   * app.post('/webhook', express.raw({type: 'application/json'}), (req, res) => {
   *   const signature = req.headers['x-signature'];
   *   const payload = req.body.toString();
   *   
   *   if (!OrvioClient.verifyWebhookSignature(payload, signature, 'secret')) {
   *     return res.status(403).send('Invalid signature');
   *   }
   *   // Handle webhook
   * });
   * ```
   */
  static verifyWebhookSignature(
    payload: string,
    signature: string,
    webhookSecret: string
  ): boolean {
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(payload)
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }
}

export type {
  OrvioClientOptions,
  CreateOtpOptions,
  CreateOtpResponse,
  VerifyOtpResponse,
  WebhookEvent
};

export default OrvioClient;
