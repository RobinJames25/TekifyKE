import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

// PayPal API configuration
const PAYPAL_API_BASE = process.env.PAYPAL_MODE === 'live'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

// Get PayPal access token
async function getPayPalAccessToken(): Promise<string> {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    throw new Error('PayPal credentials not configured');
  }

  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');

  const response = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get PayPal access token: ${error}`);
  }

  const data = await response.json();
  return data.access_token;
}

// Capture PayPal order
async function capturePayPalOrder(accessToken: string, orderId: string): Promise<any> {
  const response = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to capture PayPal order: ${error}`);
  }

  return response.json();
}

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const token = searchParams.get('token'); // PayPal order ID

    if (!token) {
      return NextResponse.redirect(
        new URL('/checkout?error=missing_token', request.url)
      );
    }

    // Find order in database by PayPal transaction reference
    const order = await prisma.order.findFirst({
      where: {
        transactionReference: token,
        paymentMethod: 'PAYPAL',
      },
      include: {
        orderItems: {
          include: {
            product: true,
          },
        },
      },
    });

    if (!order) {
      return NextResponse.redirect(
        new URL('/checkout?error=order_not_found', request.url)
      );
    }

    // Check if order is already paid
    if (order.status === 'PAID') {
      return NextResponse.redirect(
        new URL(`/orders/${order.id}?status=already_paid`, request.url)
      );
    }

    // Get PayPal access token
    const accessToken = await getPayPalAccessToken();

    // Capture the PayPal order
    const captureData = await capturePayPalOrder(accessToken, token);

    // Verify capture was successful
    if (captureData.status !== 'COMPLETED') {
      return NextResponse.redirect(
        new URL(`/orders/${order.id}?status=payment_failed`, request.url)
      );
    }

    // Update order status to PAID
    await prisma.order.update({
      where: { id: order.id },
      data: {
        status: 'PAID',
        transactionReference: captureData.id,
      },
    });

    // Update product stock
    for (const item of order.orderItems) {
      await prisma.product.update({
        where: { id: item.productId },
        data: {
          stock: {
            decrement: item.quantity,
          },
        },
      });
    }

    // Redirect to order confirmation page
    return NextResponse.redirect(
      new URL(`/orders/${order.id}?status=success`, request.url)
    );

  } catch (error) {
    console.error('PayPal capture order error:', error);
    
    // Try to get order ID from error context
    const searchParams = request.nextUrl.searchParams;
    const token = searchParams.get('token');
    
    if (token) {
      const order = await prisma.order.findFirst({
        where: { transactionReference: token },
      });
      
      if (order) {
        return NextResponse.redirect(
          new URL(`/orders/${order.id}?status=error`, request.url)
        );
      }
    }

    return NextResponse.redirect(
      new URL('/checkout?error=payment_failed', request.url)
    );
  }
}

// Made with Bob
