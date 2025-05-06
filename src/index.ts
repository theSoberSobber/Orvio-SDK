import axios, { AxiosInstance } from 'axios';
import crypto from 'crypto';

interface OrvioClientOptions {
  /** Custom base URL for the API (default: 'https://backend-orvio.1110777.xyz') */
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

  /**
   * Optional organization name to associate with the OTP request
   */
  orgName?: string;
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
  /** Optional organization name if provided when creating the OTP */
  orgName?: string;
}

/**
 * Available credit modes
 */
export type CreditMode = 'direct' | 'moderate' | 'strict';

/**
 * Account credit information
 */
interface CreditInfo {
  /** Current credit balance */
  balance: number;
  /** Current credit mode (direct, moderate, strict) */
  mode: CreditMode;
  /** Cashback points earned from sending OTPs */
  cashbackPoints: number;
}

/**
 * User stats information
 */
interface UserStats {
  provider: {
    currentDevice: null;
    allDevices: {
      failedToSendAck: number;
      sentAckNotVerified: number;
      sentAckVerified: number;
      totalMessagesSent: number;
      totalDevices: number;
      activeDevices: number;
    };
  };
  consumer: {
    aggregate: {
      totalKeys: number;
      activeKeys: number;
      oldestKey: number;
      newestKey: number;
      lastUsedKey: number;
    };
    keys: Array<{
      name: string;
      createdAt: string;
      lastUsed: string | null;
      refreshToken: string;
    }>;
  };
  credits: CreditInfo;
}

/**
 * API key information
 */
interface ApiKey {
  id: string;
  name: string;
  createdAt: string;
  lastUsed: string | null;
  session: {
    id: string;
    refreshToken: string;
  };
}

/**
 * Options for creating a new API key
 */
interface CreateApiKeyOptions {
  /** Organization name to associate with the API key */
  orgName?: string;
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
   * @example
   * ```typescript
   * // Create a client instance
   * const orvio = new OrvioClient('your-api-key');
   * 
   * // Send an OTP
   * const { tid } = await orvio.create('+1234567890');
   * 
   * // Verify an OTP
   * const result = await orvio.verify(tid, '123456');
   * 
   * // Check credits and cashback points
   * const credits = await orvio.getCredits();
   * console.log(`Balance: ${credits.balance}, Cashback: ${credits.cashbackPoints}`);
   * 
   * // Change credit mode
   * await orvio.setCreditMode('strict');
   * ```
   */
  constructor(apiKey: string, options: OrvioClientOptions = {}) {
    this.baseURL = options.baseURL || 'https://backend-orvio.1110777.xyz';
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
   *   webhookSecret: 'your_webhook_secret',
   *   orgName: 'Your Company'
   * });
   * ```
   */
  async create(phoneNumber: string, options: CreateOtpOptions = {}): Promise<CreateOtpResponse> {
    const payload = {
      phoneNumber,
      reportingWebhook: options.webhookUrl,
      reportingSecret: options.webhookSecret,
      orgName: options.orgName
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
   * Retrieves the current credit balance, mode, and cashback points
   * @returns Promise containing credit information
   * @example
   * ```typescript
   * const credits = await client.getCredits();
   * console.log(`Balance: ${credits.balance}, Mode: ${credits.mode}, Cashback: ${credits.cashbackPoints}`);
   * ```
   */
  async getCredits(): Promise<CreditInfo> {
    const response = await this.api.get<UserStats>('/auth/stats');
    return response.data.credits;
  }

  /**
   * Retrieves complete user statistics including credits, devices, and API keys
   * @returns Promise containing user statistics
   * @example
   * ```typescript
   * const stats = await client.getStats();
   * console.log(`Total messages sent: ${stats.provider.allDevices.totalMessagesSent}`);
   * ```
   */
  async getStats(): Promise<UserStats> {
    const response = await this.api.get<UserStats>('/auth/stats');
    return response.data;
  }

  /**
   * Updates the credit mode setting
   * @param mode - The credit mode to set ('direct', 'moderate', or 'strict')
   * @returns Promise containing success status
   * @example
   * ```typescript
   * await client.setCreditMode('strict');
   * ```
   * 
   * Credit modes:
   * - direct: Charges 1 credit per OTP. Credits are never refunded, even if delivery fails.
   * - moderate: Charges 1 credit per OTP. Credits refunded if delivery fails.
   * - strict: Charges 2 credits per OTP. Higher verification standards with partial refund if not verified.
   */
  async setCreditMode(mode: CreditMode): Promise<{ success: boolean }> {
    const response = await this.api.patch<{ success: boolean }>('/service/creditMode', { mode });
    return response.data;
  }

  /**
   * Retrieves all API keys associated with the account
   * @returns Promise containing an array of API keys
   * @example
   * ```typescript
   * const apiKeys = await client.getApiKeys();
   * apiKeys.forEach(key => console.log(`Key name: ${key.name}`));
   * ```
   */
  async getApiKeys(): Promise<ApiKey[]> {
    const response = await this.api.get<ApiKey[]>('/auth/apiKey/getAll');
    return response.data;
  }

  /**
   * Creates a new API key
   * @param name - Name for the new API key
   * @param options - Additional options for the new API key
   * @returns Promise containing success status
   * @example
   * ```typescript
   * await client.createApiKey('Production Key', { orgName: 'ACME Inc.' });
   * ```
   */
  async createApiKey(name: string, options: CreateApiKeyOptions = {}): Promise<void> {
    const payload = {
      name,
      orgName: options.orgName
    };
    
    await this.api.post('/auth/apiKey/createNew', payload);
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
  WebhookEvent,
  CreditInfo,
  UserStats,
  ApiKey,
  CreateApiKeyOptions
};

export default OrvioClient;
