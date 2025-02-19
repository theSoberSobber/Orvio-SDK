# Orvio SDK

Official SDK for Orvio OTP and Verification Services.

## Installation

```bash
npm install @orvio/sdk
```

## Usage
```typescript
import OrvioClient from 'orvio-sdk';

// Initialize the client
const client = new OrvioClient('your_api_key');

// Send OTP
const { tid } = await client.create('+1234567890', {
  webhookUrl: 'https://your-server.com/webhook',
  webhookSecret: 'your_webhook_secret'
});

// Verify OTP
const result = await client.verify(tid, '123456');

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
### Webhook Verification
```typescript
static verifyWebhookSignature(payload: string, signature: string, webhookSecret: string): boolean
```

## License
MIT
