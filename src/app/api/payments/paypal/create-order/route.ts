import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { prisma } from '@/lib/prisma';

// PayPal API configuration
const PAYPAL_API_BASE = process.env.PAYPAL_MODE === 'live'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

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

// Create PayPal order
async function createPayPalOrder(accessToken: string, orderData: OrderData): Promise<any> {
  const response = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      intent: 'CAPTURE',
      purchase_units: [
        {
          amount: {
            currency_code: 'USD',
            value: (orderData.total / 130).toFixed(2), // Convert KES to USD (approximate rate)
            breakdown: {
              item_total: {
                currency_code: 'USD',
                value: (orderData.subtotal / 130).toFixed(2),
              },
              shipping: {
                currency_code: 'USD',
                value: (orderData.deliveryFee / 130).toFixed(2),
              },
            },
          },
          description: 'TekifyKE Electronics Purchase',
          shipping: {
            name: {
              full_name: orderData.shippingInfo.fullName,
            },
            address: {
              address_line_1: orderData.shippingInfo.address,
              admin_area_2: orderData.shippingInfo.city,
              admin_area_1: orderData.shippingInfo.county,
              postal_code: orderData.shippingInfo.postalCode || '00100',
              country_code: 'KE',
            },
          },
        },
      ],
      application_context: {
        brand_name: 'TekifyKE',
        landing_page: 'NO_PREFERENCE',
        user_action: 'PAY_NOW',
        return_url: `${process.env.NEXT_PUBLIC_APP_URL}/api/payments/paypal/capture-order`,
        cancel_url: `${process.env.NEXT_PUBLIC_APP_URL}/checkout`,
      },
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to create PayPal order: ${error}`);
  }

  return response.json();
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
        paymentMethod: 'PAYPAL',
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

    // Get PayPal access token
    const accessToken = await getPayPalAccessToken();

    // Create PayPal order
    const paypalOrder = await createPayPalOrder(accessToken, orderData);

    // Update order with PayPal order ID
    await prisma.order.update({
      where: { id: order.id },
      data: {
        transactionReference: paypalOrder.id,
      },
    });

    // Get approval URL
    const approvalUrl = paypalOrder.links.find(
      (link: any) => link.rel === 'approve'
    )?.href;

    if (!approvalUrl) {
      throw new Error('No approval URL found in PayPal response');
    }

    return NextResponse.json({
      success: true,
      orderId: order.id,
      paypalOrderId: paypalOrder.id,
      approvalUrl,
    });

  } catch (error) {
    console.error('PayPal create order error:', error);
    return NextResponse.json(
      {
        error: 'Failed to create PayPal order',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// Made with Bob
