import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

interface KCBBuniCallbackPayload {
  Body: {
    stkCallback: {
      MerchantRequestID: string;
      CheckoutRequestID: string;
      ResultCode: number;
      ResultDesc: string;
      CallbackMetadata?: {
        Item: Array<{
          Name: string;
          Value: string | number;
        }>;
      };
    };
  };
}

// Alternative payload structure (KCB Buni may use different formats)
interface AlternativeCallbackPayload {
  merchantRequestID?: string;
  checkoutRequestID?: string;
  resultCode?: number;
  resultDesc?: string;
  amount?: number;
  mpesaReceiptNumber?: string;
  transactionDate?: string;
  phoneNumber?: string;
}

export async function POST(request: NextRequest) {
  try {
    // Parse the callback payload
    const payload: KCBBuniCallbackPayload | AlternativeCallbackPayload = await request.json();

    console.log('KCB Buni callback received:', JSON.stringify(payload, null, 2));

    // Extract data from different possible payload structures
    let checkoutRequestID: string | undefined;
    let resultCode: number | undefined;
    let resultDesc: string | undefined;
    let mpesaReceiptNumber: string | undefined;
    let amount: number | undefined;
    let phoneNumber: string | undefined;

    // Handle standard KCB Buni callback structure
    if ('Body' in payload && payload.Body?.stkCallback) {
      const callback = payload.Body.stkCallback;
      checkoutRequestID = callback.CheckoutRequestID;
      resultCode = callback.ResultCode;
      resultDesc = callback.ResultDesc;

      // Extract metadata if available
      if (callback.CallbackMetadata?.Item) {
        for (const item of callback.CallbackMetadata.Item) {
          switch (item.Name) {
            case 'Amount':
              amount = Number(item.Value);
              break;
            case 'MpesaReceiptNumber':
              mpesaReceiptNumber = String(item.Value);
              break;
            case 'PhoneNumber':
              phoneNumber = String(item.Value);
              break;
          }
        }
      }
    }
    // Handle alternative callback structure
    else if ('checkoutRequestID' in payload) {
      checkoutRequestID = payload.checkoutRequestID;
      resultCode = payload.resultCode;
      resultDesc = payload.resultDesc;
      mpesaReceiptNumber = payload.mpesaReceiptNumber;
      amount = payload.amount;
      phoneNumber = payload.phoneNumber;
    }

    if (!checkoutRequestID) {
      console.error('No checkout request ID in callback');
      return NextResponse.json(
        { error: 'Invalid callback payload' },
        { status: 400 }
      );
    }

    // Find order by transaction reference (CheckoutRequestID)
    const order = await prisma.order.findFirst({
      where: {
        transactionReference: checkoutRequestID,
        paymentMethod: 'KCB_BUNI',
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
      console.error(`Order not found for CheckoutRequestID: ${checkoutRequestID}`);
      return NextResponse.json(
        { error: 'Order not found' },
        { status: 404 }
      );
    }

    // Check if payment was successful (ResultCode 0 means success)
    if (resultCode === 0) {
      console.log(`Payment successful for order ${order.id}`);

      // Update order status to PAID
      await prisma.order.update({
        where: { id: order.id },
        data: {
          status: 'PAID',
          transactionReference: mpesaReceiptNumber || checkoutRequestID,
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

      console.log(`Order ${order.id} marked as PAID and stock updated`);
    } else {
      console.log(`Payment failed for order ${order.id}: ${resultDesc}`);

      // Optionally update order status to CANCELLED or keep as PENDING
      // For now, we'll keep it as PENDING so user can retry
      await prisma.order.update({
        where: { id: order.id },
        data: {
          // Keep status as PENDING for retry, or set to CANCELLED
          status: 'PENDING',
        },
      });
    }

    // Return success response to KCB Buni
    return NextResponse.json({
      ResultCode: 0,
      ResultDesc: 'Callback processed successfully',
    });

  } catch (error) {
    console.error('KCB Buni callback error:', error);
    
    // Still return success to KCB Buni to avoid retries
    // Log the error for manual investigation
    return NextResponse.json({
      ResultCode: 0,
      ResultDesc: 'Callback received',
    });
  }
}

// Handle GET requests (for testing/verification)
export async function GET(request: NextRequest) {
  return NextResponse.json({
    message: 'KCB Buni callback endpoint is active',
    timestamp: new Date().toISOString(),
  });
}

// Made with Bob
