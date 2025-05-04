# Orvio SDK

Official SDK for Orvio OTP and Verification Services.

## Installation

```bash
npm install @orvio/sdk
```

## Usage
```typescript
import OrvioClient from '@orvio/sdk';

// Initialize the client
const client = new OrvioClient('your_api_key');

// Send OTP
const { tid } = await client.create('+1234567890', {
  webhookUrl: 'https://your-server.com/webhook',
  webhookSecret: 'your_webhook_secret',
  orgName: 'Your Company'
});

// Verify OTP
const result = await client.verify(tid, '123456');

// Get credit information
const credits = await client.getCredits();
console.log(`Balance: ${credits.balance}, Mode: ${credits.mode}`);

// Create a new API key
await client.createApiKey('Production Key', { orgName: 'Your Company' });

// Webhook handler example (Express)
app.post('/webhook', express.raw({type: 'application/json'}), (req, res) => {
  const signature = req.headers['x-signature'] as string;
  const payload = req.body.toString();
  
  if (!OrvioClient.verifyWebhookSignature(payload, signature, 'your_webhook_secret')) {
    return res.status(403).send('Invalid signature');
  }

  const event = JSON.parse(payload);
  // Handle webhook event
  res.status(200).send('OK');
});
```

## Documentation

### Sending an OTP
```typescript
create(phoneNumber: string, options?: CreateOtpOptions): Promise<CreateOtpResponse>
```

### Verifying an OTP
```typescript
verify(tid: string, userInputOtp: string): Promise<VerifyOtpResponse>
```

### Credit Management
```typescript
getCredits(): Promise<CreditInfo>
getStats(): Promise<UserStats>
```

### API Key Management
```typescript
getApiKeys(): Promise<ApiKey[]>
createApiKey(name: string, options?: CreateApiKeyOptions): Promise<void>
```

### Webhook Verification
```typescript
static verifyWebhookSignature(payload: string, signature: string, webhookSecret: string): boolean
```

## Types

### CreateOtpOptions
```typescript
interface CreateOtpOptions {
  webhookUrl?: string;
  webhookSecret?: string;
  orgName?: string;
}
```

### CreditInfo
```typescript
interface CreditInfo {
  balance: number;
  mode: string;
}
```

### CreateApiKeyOptions
```typescript
interface CreateApiKeyOptions {
  orgName?: string;
}
```

## License
MIT
