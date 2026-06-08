# Payment Integration Guide - TekifyKE

This document provides comprehensive information about the payment integrations implemented in TekifyKE.

## Overview

TekifyKE supports two payment methods:
1. **PayPal** - International payments via credit/debit cards and PayPal accounts
2. **KCB Buni (M-Pesa)** - Local Kenyan mobile money payments via M-Pesa

## Architecture

### Payment Flow

```
User Checkout → Payment Selection → Payment Processing → Order Confirmation
     ↓                ↓                      ↓                    ↓
  Cart Page    Checkout Page         Payment API          Order Page
                                          ↓
                                    Webhook/Callback
                                          ↓
                                   Update Order Status
```

## PayPal Integration

### Configuration

Required environment variables:
```env
PAYPAL_MODE=sandbox                    # or 'live' for production
PAYPAL_CLIENT_ID=your_client_id
PAYPAL_CLIENT_SECRET=your_client_secret
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

### API Endpoints

#### 1. Create Order
**Endpoint:** `POST /api/payments/paypal/create-order`

**Request Body:**
```json
{
  "shippingInfo": {
    "fullName": "John Doe",
    "email": "john@example.com",
    "phone": "0712345678",
    "address": "123 Main St",
    "city": "Nairobi",
    "county": "Nairobi",
    "postalCode": "00100",
    "additionalInfo": "Near landmark"
  },
  "paymentMethod": "PAYPAL",
  "items": [
    {
      "productId": "product_id",
      "quantity": 1,
      "price": 50000
    }
  ],
  "subtotal": 50000,
  "deliveryFee": 0,
  "total": 50000
}
```

**Response:**
```json
{
  "success": true,
  "orderId": "order_id",
  "paypalOrderId": "paypal_order_id",
  "approvalUrl": "https://www.paypal.com/checkoutnow?token=..."
}
```

**Process:**
1. Validates user authentication
2. Verifies product availability and stock
3. Creates order in database with PENDING status
4. Generates PayPal access token
5. Creates PayPal order with shipping details
6. Returns approval URL for user to complete payment

#### 2. Capture Order
**Endpoint:** `GET /api/payments/paypal/capture-order?token=PAYPAL_ORDER_ID`

**Process:**
1. Retrieves order from database using PayPal token
2. Captures payment from PayPal
3. Updates order status to PAID
4. Decrements product stock
5. Redirects to order confirmation page

### Currency Conversion

PayPal requires USD, so KES amounts are converted:
```typescript
const usdAmount = (kesAmount / 130).toFixed(2); // Approximate rate
```

**Note:** Update the conversion rate regularly or use a currency API.

## KCB Buni (M-Pesa) Integration

### Configuration

Required environment variables:
```env
KCB_BUNI_BASE_URL=https://uat.buni.kcbgroup.com
KCB_BUNI_CLIENT_ID=your_client_id
KCB_BUNI_CLIENT_SECRET=your_client_secret
KCB_BUNI_MERCHANT_CODE=your_merchant_code
KCB_BUNI_TILL_NUMBER=your_till_number
KCB_BUNI_PASSKEY=your_passkey
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

### API Endpoints

#### 1. STK Push
**Endpoint:** `POST /api/payments/kcb-buni/stk-push`

**Request Body:**
```json
{
  "shippingInfo": {
    "fullName": "John Doe",
    "email": "john@example.com",
    "phone": "0712345678",
    "address": "123 Main St",
    "city": "Nairobi",
    "county": "Nairobi",
    "postalCode": "00100",
    "additionalInfo": "Near landmark"
  },
  "paymentMethod": "KCB_BUNI",
  "items": [
    {
      "productId": "product_id",
      "quantity": 1,
      "price": 50000
    }
  ],
  "subtotal": 50000,
  "deliveryFee": 0,
  "total": 50000
}
```

**Response:**
```json
{
  "success": true,
  "orderId": "order_id",
  "message": "STK push sent to your phone. Please enter your M-Pesa PIN to complete payment.",
  "checkoutRequestId": "ws_CO_123456789",
  "responseCode": "0",
  "responseDescription": "Success. Request accepted for processing"
}
```

**Process:**
1. Validates user authentication
2. Validates Kenyan phone number format
3. Verifies product availability and stock
4. Creates order in database with PENDING status
5. Gets OAuth2 access token from KCB Buni
6. Initiates STK push to customer's phone
7. Returns success message

#### 2. Payment Callback
**Endpoint:** `POST /api/payments/kcb-buni/callback`

**Webhook Payload (from KCB Buni):**
```json
{
  "Body": {
    "stkCallback": {
      "MerchantRequestID": "merchant_request_id",
      "CheckoutRequestID": "checkout_request_id",
      "ResultCode": 0,
      "ResultDesc": "The service request is processed successfully.",
      "CallbackMetadata": {
        "Item": [
          {
            "Name": "Amount",
            "Value": 50000
          },
          {
            "Name": "MpesaReceiptNumber",
            "Value": "QGH12345"
          },
          {
            "Name": "PhoneNumber",
            "Value": "254712345678"
          }
        ]
      }
    }
  }
}
```

**Process:**
1. Receives callback from KCB Buni
2. Extracts CheckoutRequestID and ResultCode
3. Finds order by transaction reference
4. If ResultCode is 0 (success):
   - Updates order status to PAID
   - Updates transaction reference with M-Pesa receipt
   - Decrements product stock
5. Returns success response to KCB Buni

### Phone Number Formatting

The system automatically formats phone numbers:
```typescript
// Input formats accepted:
"0712345678"    → "254712345678"
"+254712345678" → "254712345678"
"254712345678"  → "254712345678"
```

### Result Codes

- `0` - Success
- `1` - Insufficient funds
- `1032` - Request cancelled by user
- `1037` - Timeout (user didn't enter PIN)
- `2001` - Invalid phone number

## Security Considerations

### 1. Authentication
- All payment endpoints require Clerk authentication
- User ID is verified before order creation

### 2. Data Validation
- Product prices verified against database
- Stock availability checked before order creation
- Phone numbers validated with regex
- Email addresses validated with regex

### 3. Webhook Security
- Callback endpoint logs all requests
- Invalid payloads are handled gracefully
- Always returns success to prevent retries
- Errors logged for manual investigation

### 4. Environment Variables
- Never commit actual credentials
- Use different credentials for sandbox/production
- Rotate secrets regularly

## Testing

### PayPal Sandbox

1. Create sandbox accounts at https://developer.paypal.com
2. Use sandbox credentials in `.env`
3. Test with sandbox buyer account

**Test Cards:**
- Visa: 4032039668297305
- Mastercard: 5425233430109903

### KCB Buni UAT

1. Use UAT environment URL
2. Test with provided test credentials
3. Use test phone numbers provided by KCB

**Test Phone:** Contact KCB for test numbers

## Error Handling

### Common Errors

#### PayPal
- **401 Unauthorized**: Invalid credentials
- **422 Unprocessable Entity**: Invalid order data
- **500 Internal Server Error**: PayPal service issue

#### KCB Buni
- **401 Unauthorized**: Invalid OAuth credentials
- **400 Bad Request**: Invalid phone number or amount
- **500 Internal Server Error**: KCB service issue

### Error Responses

All payment endpoints return consistent error format:
```json
{
  "error": "Error message",
  "details": "Detailed error description"
}
```

## Monitoring

### Logs

Payment operations are logged:
```typescript
console.log('PayPal create order:', orderData);
console.log('KCB Buni STK push:', payload);
console.log('KCB Buni callback:', callbackData);
```

### Database Queries

Monitor order status transitions:
```sql
SELECT status, COUNT(*) 
FROM "Order" 
WHERE "createdAt" > NOW() - INTERVAL '24 hours'
GROUP BY status;
```

## Production Checklist

- [ ] Update PayPal mode to 'live'
- [ ] Use production PayPal credentials
- [ ] Update KCB Buni to production URL
- [ ] Use production KCB credentials
- [ ] Update currency conversion rate
- [ ] Set up proper logging/monitoring
- [ ] Configure webhook URLs in payment provider dashboards
- [ ] Test with real transactions (small amounts)
- [ ] Set up alerts for failed payments
- [ ] Document support procedures

## Support

### PayPal Issues
- Dashboard: https://developer.paypal.com
- Support: https://www.paypal.com/support

### KCB Buni Issues
- Contact: KCB Buni support team
- Email: support@kcbgroup.com

## API Rate Limits

### PayPal
- Sandbox: 50 requests/second
- Production: Contact PayPal for limits

### KCB Buni
- Contact KCB for rate limit information

## Troubleshooting

### Payment Not Completing

1. Check order status in database
2. Verify webhook/callback was received
3. Check payment provider dashboard
4. Review server logs for errors

### Stock Not Updating

1. Verify order status is PAID
2. Check if callback was processed
3. Manually update stock if needed

### User Not Redirected

1. Check return URLs in payment provider
2. Verify NEXT_PUBLIC_APP_URL is correct
3. Check for JavaScript errors in browser

## Future Enhancements

- [ ] Add Stripe integration
- [ ] Implement refund functionality
- [ ] Add payment retry mechanism
- [ ] Implement partial payments
- [ ] Add payment analytics dashboard
- [ ] Support multiple currencies
- [ ] Add payment installments
- [ ] Implement subscription payments