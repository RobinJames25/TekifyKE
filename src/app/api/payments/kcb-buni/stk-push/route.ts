import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { prisma } from '@/lib/prisma';

// KCB Buni API configuration
const KCB_BUNI_BASE_URL = process.env.KCB_BUNI_BASE_URL || 'https://uat.buni.kcbgroup.com';
const KCB_BUNI_CLIENT_ID = process.env.KCB_BUNI_CLIENT_ID;
const KCB_BUNI_CLIENT_SECRET = process.env.KCB_BUNI_CLIENT_SECRET;
const KCB_BUNI_MERCHANT_CODE = process.env.KCB_BUNI_MERCHANT_CODE;
const KCB_BUNI_TILL_NUMBER = process.env.KCB_BUNI_TILL_NUMBER;

interface OrderItem {
  productId: string;
  quantity: number;
  price: number;
}

interface OrderData {
  shippingInfo: {
    fullName: string;
    email: string;
    phone: string;
    address: string;
    city: string;
    county: string;
    postalCode: string;
    additionalInfo: string;
  };
  paymentMethod: string;
  items: OrderItem[];
  subtotal: number;
  deliveryFee: number;
  total: number;
}

// Get KCB Buni OAuth2 access token
async function getKCBBuniAccessToken(): Promise<string> {
  if (!KCB_BUNI_CLIENT_ID || !KCB_BUNI_CLIENT_SECRET) {
    throw new Error('KCB Buni credentials not configured');
  }

  const credentials = Buffer.from(
    `${KCB_BUNI_CLIENT_ID}:${KCB_BUNI_CLIENT_SECRET}`
  ).toString('base64');

  const response = await fetch(`${KCB_BUNI_BASE_URL}/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  if (!response.ok) {
    const error = await response.text();
    console.error('KCB Buni token error:', error);
    throw new Error(`Failed to get KCB Buni access token: ${response.status}`);
  }

  const data = await response.json();
  return data.access_token;
}

// Format phone number to KCB Buni format (254XXXXXXXXX)
function formatPhoneNumber(phone: string): string {
  // Remove all non-digit characters
  let cleaned = phone.replace(/\D/g, '');
  
  // If starts with 0, replace with 254
  if (cleaned.startsWith('0')) {
    cleaned = '254' + cleaned.substring(1);
  }
  
  // If doesn't start with 254, add it
  if (!cleaned.startsWith('254')) {
    cleaned = '254' + cleaned;
  }
  
  return cleaned;
}

// Initiate STK Push
async function initiateSTKPush(
  accessToken: string,
  phoneNumber: string,
  amount: number,
  orderId: string
): Promise<any> {
  if (!KCB_BUNI_MERCHANT_CODE || !KCB_BUNI_TILL_NUMBER) {
    throw new Error('KCB Buni merchant configuration missing');
  }

  const formattedPhone = formatPhoneNumber(phoneNumber);
  const callbackUrl = `${process.env.NEXT_PUBLIC_APP_URL}/api/payments/kcb-buni/callback`;

  const payload = {
    phoneNumber: formattedPhone,
    amount: amount.toString(),
    invoiceNumber: orderId,
    sharedShortCode: true,
    orgShortCode: KCB_BUNI_TILL_NUMBER,
    orgPassKey: process.env.KCB_BUNI_PASSKEY || '',
    callbackUrl: callbackUrl,
    transactionDescription: `TekifyKE Order ${orderId}`,
  };

  console.log('STK Push payload:', {
    ...payload,
    orgPassKey: '***REDACTED***',
  });

  const response = await fetch(`${KCB_BUNI_BASE_URL}/mm/api/request/v1/stkpush`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const responseText = await response.text();
  console.log('STK Push response:', responseText);

  if (!response.ok) {
    throw new Error(`Failed to initiate STK push: ${response.status} - ${responseText}`);
  }

  try {
    return JSON.parse(responseText);
  } catch (e) {
    throw new Error(`Invalid JSON response from KCB Buni: ${responseText}`);
  }
}

export async function POST(request: NextRequest) {
  try {
    // Authenticate user
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Parse request body
    const orderData: OrderData = await request.json();

    // Validate order data
    if (!orderData.items || orderData.items.length === 0) {
      return NextResponse.json(
        { error: 'No items in order' },
        { status: 400 }
      );
    }

    if (!orderData.shippingInfo.fullName || !orderData.shippingInfo.email || !orderData.shippingInfo.phone) {
      return NextResponse.json(
        { error: 'Missing required shipping information' },
        { status: 400 }
      );
    }

    // Validate phone number format
    const phoneRegex = /^(\+254|254|0)[17]\d{8}$/;
    if (!phoneRegex.test(orderData.shippingInfo.phone.replace(/\s/g, ''))) {
      return NextResponse.json(
        { error: 'Invalid Kenyan phone number format' },
        { status: 400 }
      );
    }

    // Verify product prices and availability
    const productIds = orderData.items.map(item => item.productId);
    const products = await prisma.product.findMany({
      where: { id: { in: productIds } },
    });

    if (products.length !== orderData.items.length) {
      return NextResponse.json(
        { error: 'Some products not found' },
        { status: 404 }
      );
    }

    // Verify stock availability
    for (const item of orderData.items) {
      const product = products.find(p => p.id === item.productId);
      if (!product) {
        return NextResponse.json(
          { error: `Product ${item.productId} not found` },
          { status: 404 }
        );
      }
      if (product.stock < item.quantity) {
        return NextResponse.json(
          { error: `Insufficient stock for ${product.name}` },
          { status: 400 }
        );
      }
    }

    // Create order in database with PENDING status
    const order = await prisma.order.create({
      data: {
        userId,
        totalAmount: orderData.total,
        status: 'PENDING',
        paymentMethod: 'KCB_BUNI',
        phoneNumber: orderData.shippingInfo.phone,
        shippingAddress: orderData.shippingInfo,
        orderItems: {
          create: orderData.items.map(item => ({
            productId: item.productId,
            quantity: item.quantity,
            price: item.price,
          })),
        },
      },
      include: {
        orderItems: true,
      },
    });

    // Get KCB Buni access token
    const accessToken = await getKCBBuniAccessToken();

    // Initiate STK Push
    const stkResponse = await initiateSTKPush(
      accessToken,
      orderData.shippingInfo.phone,
      orderData.total,
      order.id
    );

    // Update order with transaction reference
    if (stkResponse.checkoutRequestID || stkResponse.CheckoutRequestID) {
      await prisma.order.update({
        where: { id: order.id },
        data: {
          transactionReference: stkResponse.checkoutRequestID || stkResponse.CheckoutRequestID,
        },
      });
    }

    return NextResponse.json({
      success: true,
      orderId: order.id,
      message: 'STK push sent to your phone. Please enter your M-Pesa PIN to complete payment.',
      checkoutRequestId: stkResponse.checkoutRequestID || stkResponse.CheckoutRequestID,
      responseCode: stkResponse.responseCode || stkResponse.ResponseCode,
      responseDescription: stkResponse.responseDescription || stkResponse.ResponseDescription,
    });

  } catch (error) {
    console.error('KCB Buni STK push error:', error);
    return NextResponse.json(
      {
        error: 'Failed to initiate M-Pesa payment',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// Made with Bob
